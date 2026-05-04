package tech.cwvermaak.weldforge.service.scim;

import io.micrometer.core.instrument.MeterRegistry;
import jakarta.persistence.EntityNotFoundException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import tech.cwvermaak.weldforge.config.tenant.TenantAccessor;
import tech.cwvermaak.weldforge.model.ScimGroup;
import tech.cwvermaak.weldforge.model.Tenant;
import tech.cwvermaak.weldforge.model.User;
import tech.cwvermaak.weldforge.model.dto.scim.ScimGroupDto;
import tech.cwvermaak.weldforge.model.dto.scim.ScimGroupMemberDto;
import tech.cwvermaak.weldforge.model.dto.scim.ScimListResponseDto;
import tech.cwvermaak.weldforge.model.dto.scim.ScimMetaDto;
import tech.cwvermaak.weldforge.model.dto.scim.ScimPatchRequestDto;
import tech.cwvermaak.weldforge.repository.ScimGroupRepository;
import tech.cwvermaak.weldforge.repository.UserRepository;
import tech.cwvermaak.weldforge.service.GroupRoleMappingService;
import tech.cwvermaak.weldforge.service.audit.AuditService;
import tech.cwvermaak.weldforge.service.scim.ScimFilterParser.ParsedFilter;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * Tenant-scoped SCIM 2.0 group provisioning. Mirrors {@code ScimUserService}
 * — every operation is gated through {@link TenantAccessor#requireTenantId()}
 * so groups from one tenant are physically invisible to another.
 *
 * Member management is the part that matters for real provisioner flows:
 * Okta and Workday push memberships via PATCH operations on the
 * {@code members} attribute. We support {@code add}, {@code remove}, and
 * {@code replace} on that attribute, all of which look up the target
 * users by id within the same tenant — cross-tenant member assignment
 * is impossible.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class ScimGroupService {

    public static final String AUDIT_GROUP_CREATE  = "scim.group.create";
    public static final String AUDIT_GROUP_REPLACE = "scim.group.replace";
    public static final String AUDIT_GROUP_PATCH   = "scim.group.patch";
    public static final String AUDIT_GROUP_DELETE  = "scim.group.delete";
    public static final String AUDIT_MEMBER_ADD    = "scim.group.member.add";
    public static final String AUDIT_MEMBER_REMOVE = "scim.group.member.remove";

    public static final String TARGET_GROUP = "scim_group";

    private final TenantAccessor tenantAccessor;
    private final ScimGroupRepository groupRepository;
    private final UserRepository userRepository;
    private final AuditService auditService;
    private final MeterRegistry meterRegistry;
    private final GroupRoleMappingService groupRoleMappingService;

    // ---- Read paths --------------------------------------------------

    public ScimListResponseDto<ScimGroupDto> list(String filter, int startIndex, int count,
                                                  String groupLocationBase, String userLocationBase) {
        Long tid = tenantAccessor.requireTenantId();
        ParsedFilter parsed = ScimFilterParser.parse(filter);

        List<ScimGroup> matches = matchGroups(tid, parsed);
        int from = Math.max(0, startIndex - 1);
        int to   = Math.min(matches.size(), from + Math.max(0, count));
        List<ScimGroupDto> page = matches.subList(from, to).stream()
                .map(g -> toDto(g, groupLocationBase, userLocationBase))
                .toList();

        return ScimListResponseDto.<ScimGroupDto>builder()
                .totalResults(matches.size())
                .startIndex(startIndex)
                .itemsPerPage(page.size())
                .resources(page)
                .build();
    }

    public ScimGroupDto get(Long id, String groupLocationBase, String userLocationBase) {
        Long tid = tenantAccessor.requireTenantId();
        ScimGroup group = groupRepository.findByIdAndTenantId(id, tid)
                .orElseThrow(() -> new EntityNotFoundException("Group " + id + " not found"));
        return toDto(group, groupLocationBase, userLocationBase);
    }

    // ---- Write paths -------------------------------------------------

    @Transactional
    public ScimGroupDto create(ScimGroupDto incoming, String groupLocationBase, String userLocationBase) {
        Tenant tenant = tenantAccessor.requireTenant();
        if (incoming.getDisplayName() == null || incoming.getDisplayName().isBlank()) {
            throw new IllegalArgumentException("displayName is required");
        }
        if (groupRepository.existsByTenantIdAndNameIgnoreCase(tenant.getId(), incoming.getDisplayName())) {
            throw new IllegalArgumentException("displayName already in use for this tenant");
        }

        ScimGroup group = ScimGroup.builder()
                .tenant(tenant)
                .name(incoming.getDisplayName())
                .displayName(incoming.getDisplayName())
                .externalId(incoming.getExternalId())
                .members(resolveMembers(tenant.getId(), incoming.getMembers()))
                .build();
        groupRepository.save(group);
        meterRegistry.counter("sso.scim.operations", "resource", "group", "op", "create",
                "tenant", tenant.getSlug()).increment();

        auditService.log(tech.cwvermaak.weldforge.model.AuditEvent.builder()
                .eventType(AUDIT_GROUP_CREATE)
                .outcome(tech.cwvermaak.weldforge.model.AuditEvent.Outcome.SUCCESS)
                .tenant(tenant)
                .targetType(TARGET_GROUP)
                .targetId(String.valueOf(group.getId()))
                .metadata(AuditService.meta(
                        "displayName", group.getDisplayName(),
                        "external_id", group.getExternalId(),
                        "member_count", group.getMembers().size())));

        return toDto(group, groupLocationBase, userLocationBase);
    }

    @Transactional
    public ScimGroupDto replace(Long id, ScimGroupDto incoming, String groupLocationBase, String userLocationBase) {
        Long tid = tenantAccessor.requireTenantId();
        ScimGroup group = groupRepository.findByIdAndTenantId(id, tid)
                .orElseThrow(() -> new EntityNotFoundException("Group " + id + " not found"));

        if (incoming.getDisplayName() != null) {
            group.setName(incoming.getDisplayName());
            group.setDisplayName(incoming.getDisplayName());
        }
        if (incoming.getExternalId() != null) group.setExternalId(incoming.getExternalId());

        if (incoming.getMembers() != null) {
            // PUT replaces the membership wholesale.
            group.setMembers(resolveMembers(tid, incoming.getMembers()));
        }

        auditService.log(tech.cwvermaak.weldforge.model.AuditEvent.builder()
                .eventType(AUDIT_GROUP_REPLACE)
                .outcome(tech.cwvermaak.weldforge.model.AuditEvent.Outcome.SUCCESS)
                .tenant(group.getTenant())
                .targetType(TARGET_GROUP)
                .targetId(String.valueOf(group.getId()))
                .metadata(AuditService.meta("displayName", group.getDisplayName())));

        // Apply group-role mappings for all current members
        applyMappingsForGroup(group);

        return toDto(group, groupLocationBase, userLocationBase);
    }

    @Transactional
    public ScimGroupDto patch(Long id, ScimPatchRequestDto patch,
                              String groupLocationBase, String userLocationBase) {
        Long tid = tenantAccessor.requireTenantId();
        ScimGroup group = groupRepository.findByIdAndTenantId(id, tid)
                .orElseThrow(() -> new EntityNotFoundException("Group " + id + " not found"));

        if (patch == null || patch.getOperations() == null) {
            return toDto(group, groupLocationBase, userLocationBase);
        }

        int added = 0;
        int removed = 0;

        for (ScimPatchRequestDto.Operation op : patch.getOperations()) {
            if (op == null || op.getOp() == null) continue;
            String operation = op.getOp().toLowerCase();
            String path = op.getPath();
            Object value = op.getValue();

            if ("displayName".equals(path) && value instanceof String s
                    && ("replace".equals(operation) || "add".equals(operation))) {
                group.setDisplayName(s);
                group.setName(s);
                continue;
            }

            // Member operations: Okta sends path="members" with a list value
            // for both add and remove. Some clients send a single object.
            if ("members".equals(path)) {
                List<ScimGroupMemberDto> entries = coerceMembers(value);
                Set<User> users = resolveMembers(tid, entries);
                if ("add".equals(operation)) {
                    Set<User> existing = group.getMembers();
                    int before = existing.size();
                    existing.addAll(users);
                    added += existing.size() - before;
                } else if ("remove".equals(operation)) {
                    Set<Long> userIds = new HashSet<>();
                    users.forEach(u -> userIds.add(u.getId()));
                    Set<User> existing = group.getMembers();
                    int before = existing.size();
                    existing.removeIf(u -> userIds.contains(u.getId()));
                    removed += before - existing.size();
                } else if ("replace".equals(operation)) {
                    Set<User> oldMembers = new HashSet<>(group.getMembers());
                    group.setMembers(users);
                    added   += diffCount(users, oldMembers);
                    removed += diffCount(oldMembers, users);
                }
            }
        }

        auditService.log(tech.cwvermaak.weldforge.model.AuditEvent.builder()
                .eventType(AUDIT_GROUP_PATCH)
                .outcome(tech.cwvermaak.weldforge.model.AuditEvent.Outcome.SUCCESS)
                .tenant(group.getTenant())
                .targetType(TARGET_GROUP)
                .targetId(String.valueOf(group.getId()))
                .metadata(AuditService.meta(
                        "ops", patch.getOperations().size(),
                        "added", added,
                        "removed", removed)));

        if (added > 0) emitMembershipEvent(group, AUDIT_MEMBER_ADD, added);
        if (removed > 0) emitMembershipEvent(group, AUDIT_MEMBER_REMOVE, removed);

        // Apply group-role mappings for affected users
        applyMappingsForGroup(group);

        return toDto(group, groupLocationBase, userLocationBase);
    }

    @Transactional
    public void delete(Long id) {
        Long tid = tenantAccessor.requireTenantId();
        ScimGroup group = groupRepository.findByIdAndTenantId(id, tid)
                .orElseThrow(() -> new EntityNotFoundException("Group " + id + " not found"));
        groupRepository.delete(group);

        auditService.log(tech.cwvermaak.weldforge.model.AuditEvent.builder()
                .eventType(AUDIT_GROUP_DELETE)
                .outcome(tech.cwvermaak.weldforge.model.AuditEvent.Outcome.SUCCESS)
                .tenant(group.getTenant())
                .targetType(TARGET_GROUP)
                .targetId(String.valueOf(id))
                .metadata(AuditService.meta("displayName", group.getDisplayName())));
    }

    // ---- Helpers -----------------------------------------------------

    private List<ScimGroup> matchGroups(Long tid, ParsedFilter parsed) {
        if (!parsed.hasFilter()) return groupRepository.findByTenantId(tid);
        return switch (parsed.getAttribute()) {
            case "displayName" -> groupRepository.findByTenantIdAndNameIgnoreCase(tid, parsed.getStringValue())
                    .map(List::of).orElse(List.of());
            case "externalId" -> groupRepository.findByTenantIdAndExternalId(tid, parsed.getStringValue())
                    .map(List::of).orElse(List.of());
            case "id" -> {
                try {
                    yield groupRepository.findByIdAndTenantId(Long.valueOf(parsed.getStringValue()), tid)
                            .map(List::of).orElse(List.of());
                } catch (NumberFormatException e) {
                    yield List.of();
                }
            }
            default -> groupRepository.findByTenantId(tid);
        };
    }

    /**
     * Translate the SCIM member entries to actual User rows. Members whose
     * ids don't resolve inside the calling tenant are silently dropped —
     * this is a deliberate cross-tenant safeguard, not a permissive parse.
     */
    private Set<User> resolveMembers(Long tid, List<ScimGroupMemberDto> incoming) {
        if (incoming == null || incoming.isEmpty()) return new LinkedHashSet<>();
        Set<User> resolved = new LinkedHashSet<>();
        for (ScimGroupMemberDto m : incoming) {
            if (m == null || m.getValue() == null) continue;
            try {
                Long userId = Long.valueOf(m.getValue());
                Optional<User> user = userRepository.findByIdAndTenantId(userId, tid);
                user.ifPresent(resolved::add);
            } catch (NumberFormatException ignored) {
                // Some upstream provisioners send opaque ids — ignore.
            }
        }
        return resolved;
    }

    @SuppressWarnings("unchecked")
    private static List<ScimGroupMemberDto> coerceMembers(Object value) {
        if (value == null) return List.of();
        if (value instanceof List<?> list) {
            List<ScimGroupMemberDto> out = new ArrayList<>();
            for (Object o : list) {
                if (o instanceof Map<?, ?> map) {
                    out.add(ScimGroupMemberDto.builder()
                            .value(stringValue(map.get("value")))
                            .display(stringValue(map.get("display")))
                            .type(stringValue(map.get("type")))
                            .build());
                } else if (o instanceof ScimGroupMemberDto dto) {
                    out.add(dto);
                }
            }
            return out;
        }
        if (value instanceof Map<?, ?> map) {
            return List.of(ScimGroupMemberDto.builder()
                    .value(stringValue(map.get("value")))
                    .display(stringValue(map.get("display")))
                    .type(stringValue(map.get("type")))
                    .build());
        }
        return List.of();
    }

    private static String stringValue(Object o) {
        return o == null ? null : o.toString();
    }

    private static int diffCount(Set<User> a, Set<User> b) {
        Set<Long> bIds = new HashSet<>();
        b.forEach(u -> bIds.add(u.getId()));
        int count = 0;
        for (User u : a) if (!bIds.contains(u.getId())) count++;
        return count;
    }

    private void applyMappingsForGroup(ScimGroup group) {
        if (group.getMembers() == null) return;
        Long tid = group.getTenant().getId();
        for (User member : group.getMembers()) {
            try {
                groupRoleMappingService.applyMappings(tid, member.getId());
            } catch (Exception e) {
                log.warn("Failed to apply group-role mapping for user {}: {}",
                        member.getEmail(), e.getMessage());
            }
        }
    }

    private void emitMembershipEvent(ScimGroup group, String type, int delta) {
        auditService.log(tech.cwvermaak.weldforge.model.AuditEvent.builder()
                .eventType(type)
                .outcome(tech.cwvermaak.weldforge.model.AuditEvent.Outcome.SUCCESS)
                .tenant(group.getTenant())
                .targetType(TARGET_GROUP)
                .targetId(String.valueOf(group.getId()))
                .metadata(AuditService.meta(
                        "displayName", group.getDisplayName(),
                        "delta", delta)));
    }

    static ScimGroupDto toDto(ScimGroup group, String groupLocationBase, String userLocationBase) {
        List<ScimGroupMemberDto> members = group.getMembers() == null ? List.of()
                : group.getMembers().stream()
                        .map(u -> ScimGroupMemberDto.builder()
                                .value(String.valueOf(u.getId()))
                                .display(u.getEmail())
                                .type("User")
                                .ref(userLocationBase == null ? null : userLocationBase + "/" + u.getId())
                                .build())
                        .toList();
        return ScimGroupDto.builder()
                .id(String.valueOf(group.getId()))
                .externalId(group.getExternalId())
                .displayName(group.getDisplayName())
                .members(members)
                .meta(ScimMetaDto.builder()
                        .resourceType("Group")
                        .created(group.getCreatedAt())
                        .lastModified(group.getUpdatedAt() != null ? group.getUpdatedAt() : LocalDateTime.now())
                        .location(groupLocationBase == null ? null : groupLocationBase + "/" + group.getId())
                        .build())
                .build();
    }
}
