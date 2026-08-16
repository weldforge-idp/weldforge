package tech.cwvermaak.weldforge.service.scim;

import io.micrometer.core.instrument.MeterRegistry;
import jakarta.persistence.EntityNotFoundException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import tech.cwvermaak.weldforge.config.tenant.TenantAccessor;
import tech.cwvermaak.weldforge.model.AuthProvider;
import tech.cwvermaak.weldforge.model.Tenant;
import tech.cwvermaak.weldforge.model.User;
import tech.cwvermaak.weldforge.model.dto.scim.ScimEmailDto;
import tech.cwvermaak.weldforge.model.dto.scim.ScimListResponseDto;
import tech.cwvermaak.weldforge.model.dto.scim.ScimMetaDto;
import tech.cwvermaak.weldforge.model.dto.scim.ScimNameDto;
import tech.cwvermaak.weldforge.model.dto.scim.ScimPatchRequestDto;
import tech.cwvermaak.weldforge.model.dto.scim.ScimUserDto;
import tech.cwvermaak.weldforge.repository.UserRepository;
import tech.cwvermaak.weldforge.service.audit.AuditEventTypes;
import tech.cwvermaak.weldforge.service.audit.AuditService;
import tech.cwvermaak.weldforge.service.scim.ScimFilterParser.ParsedFilter;

import java.time.LocalDateTime;
import java.util.List;

/**
 * Tenant-scoped SCIM 2.0 user provisioning. The shape of every method
 * mirrors what an upstream provisioner (Okta, Workday, Entra ID) actually
 * sends:
 *
 *   GET    /Users?filter=userName eq "alice@acme.test"   → list/find
 *   POST   /Users                                        → create
 *   GET    /Users/{id}                                   → get
 *   PUT    /Users/{id}                                   → full replace
 *   PATCH  /Users/{id}                                   → partial update
 *   DELETE /Users/{id}                                   → hard delete
 *
 * Every operation passes through {@link TenantAccessor#requireTenantId()}
 * so cross-tenant access is impossible by construction. PATCH on
 * {@code active} is the deactivation hook the PRD requires (PRV-03):
 * flipping it to false propagates immediately because login refuses
 * inactive accounts.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class ScimUserService {

    public static final String AUDIT_SCIM_USER_CREATE   = "scim.user.create";
    public static final String AUDIT_SCIM_USER_REPLACE  = "scim.user.replace";
    public static final String AUDIT_SCIM_USER_PATCH    = "scim.user.patch";
    public static final String AUDIT_SCIM_USER_DEACTIVATE = "scim.user.deactivate";
    public static final String AUDIT_SCIM_USER_REACTIVATE = "scim.user.reactivate";
    public static final String AUDIT_SCIM_USER_DELETE   = "scim.user.delete";

    private final TenantAccessor tenantAccessor;
    private final UserRepository userRepository;
    private final AuditService auditService;
    private final MeterRegistry meterRegistry;
    private final tech.cwvermaak.weldforge.service.TenantSeatService seatService;

    // ---- Read paths --------------------------------------------------

    public ScimListResponseDto<ScimUserDto> list(String filter, int startIndex, int count, String location) {
        Long tid = tenantAccessor.requireTenantId();
        ParsedFilter parsed = ScimFilterParser.parse(filter);

        List<User> matches = matchUsers(tid, parsed);
        // SCIM startIndex is 1-based per RFC 7644 §3.4.2.4.
        int from = Math.max(0, startIndex - 1);
        int to   = Math.min(matches.size(), from + Math.max(0, count));
        List<ScimUserDto> page = matches.subList(from, to).stream()
                .map(u -> toDto(u, location))
                .toList();

        return ScimListResponseDto.<ScimUserDto>builder()
                .totalResults(matches.size())
                .startIndex(startIndex)
                .itemsPerPage(page.size())
                .resources(page)
                .build();
    }

    public ScimUserDto get(Long id, String location) {
        Long tid = tenantAccessor.requireTenantId();
        User user = userRepository.findByIdAndTenantId(id, tid)
                .orElseThrow(() -> new EntityNotFoundException("User " + id + " not found"));
        return toDto(user, location);
    }

    // ---- Write paths -------------------------------------------------

    @Transactional
    public ScimUserDto create(ScimUserDto incoming, String location) {
        Tenant tenant = tenantAccessor.requireTenant();
        if (incoming.getUserName() == null || incoming.getUserName().isBlank()) {
            throw new IllegalArgumentException("userName is required");
        }

        // Reject duplicates inside the tenant — the unique index would
        // catch it anyway, but a clean error is friendlier than an SQL
        // constraint violation surfacing as a 500.
        if (userRepository.findByTenantIdAndUsernameIgnoreCase(tenant.getId(), incoming.getUserName()).isPresent()) {
            throw new IllegalArgumentException("userName already in use for this tenant");
        }
        String email = primaryEmail(incoming);
        if (email == null) email = incoming.getUserName();

        // An inactive user consumes no seat, so only guard when the incoming
        // record would land active.
        if (incoming.isActive()) {
            seatService.assertCapacity(tenant);
        }

        User user = User.builder()
                .tenant(tenant)
                .username(incoming.getUserName())
                .email(email)
                .name(displayName(incoming))
                .provider(AuthProvider.LOCAL) // SCIM-provisioned, no upstream IdP
                .providerId("scim:" + (incoming.getExternalId() != null ? incoming.getExternalId() : incoming.getUserName()))
                .active(incoming.isActive())
                .build();
        userRepository.save(user);
        meterRegistry.counter("sso.scim.operations", "resource", "user", "op", "create",
                "tenant", tenant.getSlug()).increment();

        auditService.log(tech.cwvermaak.weldforge.model.AuditEvent.builder()
                .eventType(AUDIT_SCIM_USER_CREATE)
                .outcome(tech.cwvermaak.weldforge.model.AuditEvent.Outcome.SUCCESS)
                .tenant(tenant)
                .targetType(AuditEventTypes.TARGET_USER)
                .targetId(String.valueOf(user.getId()))
                .metadata(AuditService.meta(
                        "userName", user.getUsername(),
                        "external_id", incoming.getExternalId())));

        return toDto(user, location);
    }

    @Transactional
    public ScimUserDto replace(Long id, ScimUserDto incoming, String location) {
        Long tid = tenantAccessor.requireTenantId();
        User user = userRepository.findByIdAndTenantId(id, tid)
                .orElseThrow(() -> new EntityNotFoundException("User " + id + " not found"));

        if (incoming.getUserName() != null) user.setUsername(incoming.getUserName());
        String email = primaryEmail(incoming);
        if (email != null) user.setEmail(email);
        String name = displayName(incoming);
        if (name != null) user.setName(name);

        boolean wasActive = user.isActive();
        boolean activeChanged = wasActive != incoming.isActive();
        user.setActive(incoming.isActive());
        seatService.assertCapacityForActivation(user.getTenant(), user, wasActive);

        auditService.log(tech.cwvermaak.weldforge.model.AuditEvent.builder()
                .eventType(AUDIT_SCIM_USER_REPLACE)
                .outcome(tech.cwvermaak.weldforge.model.AuditEvent.Outcome.SUCCESS)
                .tenant(user.getTenant())
                .targetType(AuditEventTypes.TARGET_USER)
                .targetId(String.valueOf(user.getId()))
                .metadata(AuditService.meta("userName", user.getUsername())));

        if (activeChanged) emitActiveAudit(user);
        return toDto(user, location);
    }

    @Transactional
    public ScimUserDto patch(Long id, ScimPatchRequestDto patch, String location) {
        Long tid = tenantAccessor.requireTenantId();
        User user = userRepository.findByIdAndTenantId(id, tid)
                .orElseThrow(() -> new EntityNotFoundException("User " + id + " not found"));

        if (patch == null || patch.getOperations() == null) {
            return toDto(user, location);
        }

        boolean wasActive = user.isActive();

        for (ScimPatchRequestDto.Operation op : patch.getOperations()) {
            if (op == null || op.getOp() == null) continue;
            String operation = op.getOp().toLowerCase();
            String path = op.getPath();
            Object value = op.getValue();

            if (!"replace".equals(operation) && !"add".equals(operation)) {
                // remove and other ops aren't supported in this pass.
                continue;
            }

            if ("active".equals(path)) {
                user.setActive(coerceBoolean(value));
            } else if ("userName".equals(path) && value instanceof String s) {
                user.setUsername(s);
            } else if ("displayName".equals(path) && value instanceof String s) {
                user.setName(s);
            } else if (path == null && value instanceof java.util.Map<?, ?> map) {
                // Some clients send the bag of attributes with no path.
                if (map.get("active") != null) user.setActive(coerceBoolean(map.get("active")));
                if (map.get("userName") instanceof String s) user.setUsername(s);
                if (map.get("displayName") instanceof String s) user.setName(s);
            }
        }

        // The loop above may have flipped `active`; a PATCH that reactivates
        // a user consumes a seat exactly like a create does.
        seatService.assertCapacityForActivation(user.getTenant(), user, wasActive);

        auditService.log(tech.cwvermaak.weldforge.model.AuditEvent.builder()
                .eventType(AUDIT_SCIM_USER_PATCH)
                .outcome(tech.cwvermaak.weldforge.model.AuditEvent.Outcome.SUCCESS)
                .tenant(user.getTenant())
                .targetType(AuditEventTypes.TARGET_USER)
                .targetId(String.valueOf(user.getId()))
                .metadata(AuditService.meta("ops", patch.getOperations().size())));

        if (wasActive != user.isActive()) emitActiveAudit(user);
        return toDto(user, location);
    }

    @Transactional
    public void delete(Long id) {
        Long tid = tenantAccessor.requireTenantId();
        User user = userRepository.findByIdAndTenantId(id, tid)
                .orElseThrow(() -> new EntityNotFoundException("User " + id + " not found"));
        userRepository.delete(user);

        auditService.log(tech.cwvermaak.weldforge.model.AuditEvent.builder()
                .eventType(AUDIT_SCIM_USER_DELETE)
                .outcome(tech.cwvermaak.weldforge.model.AuditEvent.Outcome.SUCCESS)
                .tenant(user.getTenant())
                .targetType(AuditEventTypes.TARGET_USER)
                .targetId(String.valueOf(id))
                .metadata(AuditService.meta("userName", user.getUsername())));
    }

    // ---- Helpers -----------------------------------------------------

    private List<User> matchUsers(Long tid, ParsedFilter parsed) {
        if (!parsed.hasFilter()) {
            return userRepository.findByTenantId(tid);
        }
        return switch (parsed.getAttribute()) {
            case "userName" -> userRepository.findByTenantIdAndUsernameIgnoreCase(tid, parsed.getStringValue())
                    .map(List::of).orElse(List.of());
            case "email", "emails", "emails.value" ->
                    userRepository.findByTenantIdAndEmailIgnoreCase(tid, parsed.getStringValue())
                    .map(List::of).orElse(List.of());
            case "active" -> userRepository.findByTenantId(tid).stream()
                    .filter(u -> u.isActive() == Boolean.TRUE.equals(parsed.getBooleanValue()))
                    .toList();
            case "id" -> {
                try {
                    yield userRepository.findByIdAndTenantId(Long.valueOf(parsed.getStringValue()), tid)
                            .map(List::of).orElse(List.of());
                } catch (NumberFormatException e) {
                    yield List.of();
                }
            }
            default -> userRepository.findByTenantId(tid);
        };
    }

    private void emitActiveAudit(User user) {
        String type = user.isActive() ? AUDIT_SCIM_USER_REACTIVATE : AUDIT_SCIM_USER_DEACTIVATE;
        auditService.log(tech.cwvermaak.weldforge.model.AuditEvent.builder()
                .eventType(type)
                .outcome(tech.cwvermaak.weldforge.model.AuditEvent.Outcome.SUCCESS)
                .tenant(user.getTenant())
                .targetType(AuditEventTypes.TARGET_USER)
                .targetId(String.valueOf(user.getId()))
                .metadata(AuditService.meta(
                        "userName", user.getUsername(),
                        "active", user.isActive())));
    }

    private static String primaryEmail(ScimUserDto dto) {
        if (dto.getEmails() == null || dto.getEmails().isEmpty()) return null;
        return dto.getEmails().stream()
                .filter(e -> Boolean.TRUE.equals(e.getPrimary()))
                .map(ScimEmailDto::getValue)
                .findFirst()
                .orElse(dto.getEmails().get(0).getValue());
    }

    private static String displayName(ScimUserDto dto) {
        if (dto.getDisplayName() != null && !dto.getDisplayName().isBlank()) return dto.getDisplayName();
        if (dto.getName() == null) return null;
        ScimNameDto n = dto.getName();
        if (n.getFormatted() != null && !n.getFormatted().isBlank()) return n.getFormatted();
        if (n.getGivenName() != null || n.getFamilyName() != null) {
            String g = n.getGivenName() == null ? "" : n.getGivenName();
            String f = n.getFamilyName() == null ? "" : n.getFamilyName();
            return (g + " " + f).trim();
        }
        return null;
    }

    private static boolean coerceBoolean(Object value) {
        if (value instanceof Boolean b) return b;
        if (value instanceof String s) return Boolean.parseBoolean(s);
        return false;
    }

    static ScimUserDto toDto(User user, String locationBase) {
        return ScimUserDto.builder()
                .id(String.valueOf(user.getId()))
                .userName(user.getUsername())
                .displayName(user.getName())
                .name(user.getName() == null ? null : ScimNameDto.builder()
                        .formatted(user.getName())
                        .build())
                .emails(List.of(ScimEmailDto.builder()
                        .value(user.getEmail())
                        .primary(true)
                        .type("work")
                        .build()))
                .active(user.isActive())
                .meta(ScimMetaDto.builder()
                        .resourceType("User")
                        .created(user.getCreatedAt())
                        .lastModified(LocalDateTime.now())
                        .location(locationBase == null ? null : locationBase + "/" + user.getId())
                        .build())
                .build();
    }
}
