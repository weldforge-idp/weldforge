package tech.cwvermaak.intellisso.service;

import jakarta.persistence.EntityNotFoundException;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import tech.cwvermaak.intellisso.config.tenant.TenantAccessor;
import tech.cwvermaak.intellisso.model.Tenant;
import tech.cwvermaak.intellisso.model.TenantTwilioProvider;
import tech.cwvermaak.intellisso.model.User;
import tech.cwvermaak.intellisso.model.dto.TwilioProviderDto;
import tech.cwvermaak.intellisso.repository.TenantRepository;
import tech.cwvermaak.intellisso.repository.TenantTwilioProviderRepository;
import tech.cwvermaak.intellisso.repository.UserRepository;
import tech.cwvermaak.intellisso.service.audit.AuditEventTypes;
import tech.cwvermaak.intellisso.service.audit.AuditService;

/**
 * Admin operations on the per-tenant Twilio configuration. Mirrors the
 * {@link TenantSamlService} pattern: every call is gated by
 * {@link TenantAccessor#requireSameTenant(Long)} so tenant A can never
 * read or mutate tenant B's credentials.
 *
 * The {@code authToken} field is write-only — it is never returned in
 * GET responses. Leaving it blank on update means "keep existing".
 */
@Service
@RequiredArgsConstructor
public class TenantTwilioService {

    private final TenantAccessor tenantAccessor;
    private final TenantRepository tenantRepository;
    private final TenantTwilioProviderRepository twilioRepository;
    private final UserRepository userRepository;
    private final AuditService auditService;
    private final TwilioService twilioService;

    public TwilioProviderDto get(Long tenantId) {
        Tenant t = tenantRepository.findById(tenantId)
                .orElseThrow(() -> new EntityNotFoundException("Tenant " + tenantId + " not found"));
        tenantAccessor.requireSameTenant(t.getId());
        return twilioRepository.findByTenantId(tenantId)
                .map(TenantTwilioService::toDto)
                .orElse(null);
    }

    @Transactional
    public TwilioProviderDto upsert(Long tenantId, TwilioProviderDto dto) {
        Tenant tenant = tenantRepository.findById(tenantId)
                .orElseThrow(() -> new EntityNotFoundException("Tenant " + tenantId + " not found"));
        tenantAccessor.requireSameTenant(tenant.getId());

        TenantTwilioProvider existing = twilioRepository.findByTenantId(tenantId).orElse(null);

        if (existing == null) {
            require(dto.getAccountSid(), "accountSid");
            require(dto.getAuthToken(),  "authToken");
            require(dto.getFromPhone(),  "fromPhone");

            TenantTwilioProvider fresh = TenantTwilioProvider.builder()
                    .tenant(tenant)
                    .accountSid(dto.getAccountSid().trim())
                    .authToken(dto.getAuthToken())
                    .fromPhone(dto.getFromPhone().trim())
                    .messagingServiceSid(trimToNull(dto.getMessagingServiceSid()))
                    .enabled(dto.getEnabled() == null ? true : dto.getEnabled())
                    .build();
            TenantTwilioProvider saved = twilioRepository.save(fresh);

            auditService.recordAdmin(AuditEventTypes.TWILIO_PROVIDER_UPSERT, currentActor(),
                    AuditEventTypes.TARGET_TWILIO_PROVIDER, String.valueOf(saved.getId()),
                    AuditService.meta(
                            "tenant", tenant.getSlug(),
                            "account_sid", maskSid(saved.getAccountSid()),
                            "from_phone", saved.getFromPhone(),
                            "created", true));
            twilioService.invalidateCache(tenantId);
            return toDto(saved);
        }

        // Update — blank authToken means "keep existing".
        if (dto.getAccountSid() != null && !dto.getAccountSid().isBlank()) {
            existing.setAccountSid(dto.getAccountSid().trim());
        }
        if (dto.getAuthToken() != null && !dto.getAuthToken().isBlank()) {
            existing.setAuthToken(dto.getAuthToken());
        }
        if (dto.getFromPhone() != null && !dto.getFromPhone().isBlank()) {
            existing.setFromPhone(dto.getFromPhone().trim());
        }
        if (dto.getMessagingServiceSid() != null) {
            existing.setMessagingServiceSid(trimToNull(dto.getMessagingServiceSid()));
        }
        if (dto.getEnabled() != null) {
            existing.setEnabled(dto.getEnabled());
        }

        auditService.recordAdmin(AuditEventTypes.TWILIO_PROVIDER_UPSERT, currentActor(),
                AuditEventTypes.TARGET_TWILIO_PROVIDER, String.valueOf(existing.getId()),
                AuditService.meta(
                        "tenant", tenant.getSlug(),
                        "account_sid", maskSid(existing.getAccountSid()),
                        "created", false));
        twilioService.invalidateCache(tenantId);
        return toDto(existing);
    }

    @Transactional
    public void delete(Long tenantId) {
        Tenant tenant = tenantRepository.findById(tenantId)
                .orElseThrow(() -> new EntityNotFoundException("Tenant " + tenantId + " not found"));
        tenantAccessor.requireSameTenant(tenant.getId());

        twilioRepository.findByTenantId(tenantId).ifPresent(row -> {
            twilioRepository.delete(row);
            auditService.recordAdmin(AuditEventTypes.TWILIO_PROVIDER_DELETE, currentActor(),
                    AuditEventTypes.TARGET_TWILIO_PROVIDER, String.valueOf(row.getId()),
                    AuditService.meta("tenant", tenant.getSlug()));
            twilioService.invalidateCache(tenantId);
        });
    }

    // ---- Helpers ----------------------------------------------------

    private User currentActor() {
        String tenantSlug = tech.cwvermaak.intellisso.config.tenant.TenantContext.get();
        var auth = org.springframework.security.core.context.SecurityContextHolder.getContext().getAuthentication();
        if (tenantSlug == null || auth == null || !(auth.getPrincipal() instanceof String email)) return null;
        return userRepository.findByTenant_SlugAndEmailIgnoreCase(tenantSlug, email).orElse(null);
    }

    static TwilioProviderDto toDto(TenantTwilioProvider p) {
        return TwilioProviderDto.builder()
                .id(p.getId())
                .tenantId(p.getTenant().getId())
                .accountSid(p.getAccountSid())
                // authToken intentionally omitted — write-only field
                .fromPhone(p.getFromPhone())
                .messagingServiceSid(p.getMessagingServiceSid())
                .enabled(p.getEnabled())
                .authTokenSet(p.getAuthToken() != null && !p.getAuthToken().isBlank())
                .build();
    }

    private static String maskSid(String sid) {
        if (sid == null || sid.length() < 8) return "***";
        return sid.substring(0, 4) + "..." + sid.substring(sid.length() - 4);
    }

    private static void require(String v, String field) {
        if (v == null || v.isBlank()) throw new IllegalArgumentException(field + " is required");
    }

    private static String trimToNull(String s) {
        if (s == null) return null;
        String t = s.trim();
        return t.isEmpty() ? null : t;
    }
}
