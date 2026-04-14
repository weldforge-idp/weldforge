package tech.cwvermaak.intellisso.service.crm;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import tech.cwvermaak.intellisso.model.CrmProvisioningLog;
import tech.cwvermaak.intellisso.model.Tenant;
import tech.cwvermaak.intellisso.model.TenantCrmProvider;
import tech.cwvermaak.intellisso.model.User;
import tech.cwvermaak.intellisso.repository.CrmProvisioningLogRepository;
import tech.cwvermaak.intellisso.repository.TenantCrmProviderRepository;
import tech.cwvermaak.intellisso.service.audit.AuditEventTypes;
import tech.cwvermaak.intellisso.service.audit.AuditService;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Orchestrates CRM pushes after identity events (PRD §3.10). The
 * default trigger is a successful login — see the hook in
 * {@link tech.cwvermaak.intellisso.service.AuthService} — but any
 * caller can invoke this directly from another lifecycle point
 * (profile update, role assignment, SCIM create) without further
 * changes here.
 *
 * <p>Per tenant:
 * <ol>
 *   <li>Walk enabled {@link TenantCrmProvider}s.</li>
 *   <li>Apply the provider's field mappings to build the outgoing
 *       payload (PRD CRM-03).</li>
 *   <li>Look up {@link CrmProvisioningLog} by (provider, user) or
 *       {@code matchKeyValue} to decide upsert-vs-create (PRD CRM-04).</li>
 *   <li>Dispatch via {@link CrmClient}, record the outcome in the log
 *       row, audit.</li>
 * </ol>
 *
 * <p>This method is {@code fire-and-forget} from the caller's point of
 * view: any exception is caught so a CRM outage never breaks a login.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class CrmProvisioningService {

    private final TenantCrmProviderRepository providerRepository;
    private final CrmProvisioningLogRepository logRepository;
    private final CrmClient crmClient;
    private final AuditService auditService;

    /**
     * Push the user's identity to every enabled CRM provider for their
     * tenant. Safe to call inline on the login success path — failures
     * are swallowed and surfaced only through the log + audit stream.
     */
    @Transactional
    public void provisionOnEvent(String eventType, User user) {
        if (user == null || user.getTenant() == null) return;
        Tenant tenant = user.getTenant();
        try {
            List<TenantCrmProvider> providers = providerRepository.findByTenantIdAndEnabledTrue(tenant.getId());
            for (TenantCrmProvider provider : providers) {
                provisionOne(provider, tenant, user, eventType);
            }
        } catch (Exception e) {
            log.warn("CRM provisioning for event {} user {} failed: {}",
                    eventType, user.getId(), e.getMessage());
        }
    }

    private void provisionOne(TenantCrmProvider provider, Tenant tenant, User user, String eventType) {
        Map<String, Object> fields = applyFieldMappings(provider, user, eventType);

        String matchKeyValue = buildMatchKeyValue(provider, user, fields);
        CrmProvisioningLog logRow = findExistingLog(provider, user, matchKeyValue)
                .orElseGet(() -> CrmProvisioningLog.builder()
                        .provider(provider)
                        .tenant(tenant)
                        .user(user)
                        .matchKeyValue(matchKeyValue)
                        .status(CrmProvisioningLog.Status.PENDING)
                        .build());

        logRow.setLastEventType(eventType);
        logRow.setAttempts(logRow.getAttempts() + 1);
        logRow.setUpdatedAt(LocalDateTime.now());

        String existingExternalId = logRow.getExternalId();
        CrmClient.Result result = crmClient.upsert(provider, existingExternalId, fields);

        if (result.success()) {
            if (logRow.getExternalId() == null && result.externalId() != null) {
                logRow.setExternalId(result.externalId());
            }
            logRow.setStatus(CrmProvisioningLog.Status.SUCCESS);
            logRow.setLastError(null);
        } else {
            logRow.setStatus(CrmProvisioningLog.Status.FAILED);
            logRow.setLastError(result.error());
        }
        logRepository.save(logRow);

        auditService.recordUserAction(AuditEventTypes.CRM_PROVISIONED, user,
                AuditEventTypes.TARGET_CRM_PROVIDER, String.valueOf(provider.getId()),
                AuditService.meta(
                        "provider_type", provider.getProviderType().name(),
                        "outcome", result.success() ? "SUCCESS" : "FAILED",
                        "external_id", logRow.getExternalId(),
                        "event", eventType));
    }

    /**
     * Walk the provider's field_mappings list and copy values off the
     * user into a flat map keyed by the CRM-side field name. The
     * {@code source} side supports a small DSL: bare attribute names
     * ({@code email}, {@code name}, {@code username}), the synthetic
     * {@code auth.timestamp} for when the event was raised, and
     * {@code event.type} for the triggering event.
     */
    private Map<String, Object> applyFieldMappings(TenantCrmProvider provider, User user, String eventType) {
        Map<String, Object> out = new LinkedHashMap<>();
        List<Map<String, Object>> mappings = provider.getFieldMappings();
        if (mappings == null) return out;

        for (Map<String, Object> mapping : mappings) {
            Object src = mapping.get("source");
            Object tgt = mapping.get("target");
            if (!(src instanceof String source) || !(tgt instanceof String target)) continue;

            Object value = resolveSource(source, user, eventType);
            if (value != null) out.put(target, value);
        }
        return out;
    }

    private Object resolveSource(String source, User user, String eventType) {
        return switch (source) {
            case "id" -> user.getId();
            case "email" -> user.getEmail();
            case "username" -> user.getUsername();
            case "name" -> user.getName();
            case "image_url" -> user.getImageUrl();
            case "provider" -> user.getProvider() == null ? null : user.getProvider().name();
            case "admin_role" -> user.getAdminRole() == null ? null : user.getAdminRole().name();
            case "role" -> user.getRole() == null ? null : user.getRole().getName();
            case "tenant_slug" -> user.getTenant() == null ? null : user.getTenant().getSlug();
            case "auth.timestamp" -> LocalDateTime.now().toString();
            case "event.type" -> eventType;
            default -> null;
        };
    }

    private String buildMatchKeyValue(TenantCrmProvider provider, User user, Map<String, Object> fields) {
        List<String> keys = provider.getMatchKeys();
        if (keys == null || keys.isEmpty()) return null;
        List<String> parts = new ArrayList<>(keys.size());
        for (String key : keys) {
            Object value = resolveSource(key, user, null);
            parts.add(value == null ? "" : value.toString().toLowerCase());
        }
        return String.join("|", parts);
    }

    private Optional<CrmProvisioningLog> findExistingLog(TenantCrmProvider provider, User user, String matchKeyValue) {
        Optional<CrmProvisioningLog> direct =
                logRepository.findByProviderIdAndUserId(provider.getId(), user.getId());
        if (direct.isPresent()) return direct;
        if (provider.isDedupeEnabled() && matchKeyValue != null && !matchKeyValue.isEmpty()) {
            return logRepository.findByProviderIdAndMatchKeyValue(provider.getId(), matchKeyValue);
        }
        return Optional.empty();
    }
}
