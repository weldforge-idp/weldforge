package tech.cwvermaak.weldforge.service;

import jakarta.persistence.EntityNotFoundException;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import tech.cwvermaak.weldforge.config.tenant.TenantAccessor;
import tech.cwvermaak.weldforge.model.Tenant;
import tech.cwvermaak.weldforge.model.TenantSamlProvider;
import tech.cwvermaak.weldforge.model.User;
import tech.cwvermaak.weldforge.model.dto.SamlProviderDto;
import tech.cwvermaak.weldforge.repository.TenantRepository;
import tech.cwvermaak.weldforge.repository.TenantSamlProviderRepository;
import tech.cwvermaak.weldforge.repository.UserRepository;
import tech.cwvermaak.weldforge.service.audit.AuditEventTypes;
import tech.cwvermaak.weldforge.service.audit.AuditService;

import java.util.List;
import java.util.regex.Pattern;

/**
 * Tenant-scoped admin operations for SAML upstream IdPs. Every call goes
 * through {@link TenantAccessor#requireSameTenant(Long)} so that tenant A can
 * never read or mutate tenant B's SAML config.
 */
@Service
@RequiredArgsConstructor
public class TenantSamlService {

    private static final Pattern PROVIDER_KEY_FORMAT =
            Pattern.compile("^[a-z0-9][a-z0-9-]{0,62}[a-z0-9]$");

    private final TenantAccessor tenantAccessor;
    private final TenantRepository tenantRepository;
    private final TenantSamlProviderRepository samlRepository;
    private final UserRepository userRepository;
    private final AuditService auditService;

    public List<SamlProviderDto> list(Long tenantId) {
        tenantAccessor.requireAnyAdmin();
        Tenant t = tenantRepository.findById(tenantId)
                .orElseThrow(() -> new EntityNotFoundException("Tenant " + tenantId + " not found"));
        tenantAccessor.requireSameTenant(t.getId());
        return samlRepository.findByTenantId(tenantId).stream()
                .map(p -> toDto(p, t.getSlug(), true))
                .toList();
    }

    @Transactional
    public SamlProviderDto upsert(Long tenantId, SamlProviderDto dto) {
        tenantAccessor.requireTenantAdmin();
        Tenant tenant = tenantRepository.findById(tenantId)
                .orElseThrow(() -> new EntityNotFoundException("Tenant " + tenantId + " not found"));
        tenantAccessor.requireSameTenant(tenant.getId());

        String key = requireKey(dto.getProviderKey());

        TenantSamlProvider existing = samlRepository
                .findByTenantIdAndProviderKey(tenantId, key)
                .orElse(null);

        if (existing == null) {
            require(dto.getIdpEntityId(),          "idpEntityId");
            require(dto.getIdpSsoUrl(),            "idpSsoUrl");
            require(dto.getIdpSigningCertificate(),"idpSigningCertificate");

            TenantSamlProvider fresh = TenantSamlProvider.builder()
                    .tenant(tenant)
                    .providerKey(key)
                    .displayName(dto.getDisplayName())
                    .idpEntityId(dto.getIdpEntityId())
                    .idpSsoUrl(dto.getIdpSsoUrl())
                    .idpSloUrl(dto.getIdpSloUrl())
                    .ssoBinding(dto.getSsoBinding() == null ? TenantSamlProvider.Binding.POST : dto.getSsoBinding())
                    .idpSigningCertificate(dto.getIdpSigningCertificate())
                    .nameIdFormat(dto.getNameIdFormat())
                    .emailAttribute(dto.getEmailAttribute() != null ? dto.getEmailAttribute() : "email")
                    .nameAttribute(dto.getNameAttribute()   != null ? dto.getNameAttribute()  : "name")
                    .wantAssertionsSigned(dto.getWantAssertionsSigned() == null ? true : dto.getWantAssertionsSigned())
                    .wantAuthnRequestSigned(Boolean.TRUE.equals(dto.getWantAuthnRequestSigned()))
                    .enabled(dto.getEnabled() == null ? true : dto.getEnabled())
                    .build();
            TenantSamlProvider saved = samlRepository.save(fresh);
            auditService.recordAdmin(AuditEventTypes.SAML_PROVIDER_UPSERT, currentActor(),
                    AuditEventTypes.TARGET_SAML_PROVIDER, String.valueOf(saved.getId()),
                    AuditService.meta("tenant", tenant.getSlug(), "providerKey", saved.getProviderKey(), "created", true));
            return toDto(saved, tenant.getSlug(), true);
        }

        if (dto.getDisplayName() != null)            existing.setDisplayName(dto.getDisplayName());
        if (dto.getIdpEntityId() != null)            existing.setIdpEntityId(dto.getIdpEntityId());
        if (dto.getIdpSsoUrl() != null)              existing.setIdpSsoUrl(dto.getIdpSsoUrl());
        if (dto.getIdpSloUrl() != null)              existing.setIdpSloUrl(dto.getIdpSloUrl());
        if (dto.getSsoBinding() != null)             existing.setSsoBinding(dto.getSsoBinding());
        if (dto.getIdpSigningCertificate() != null && !dto.getIdpSigningCertificate().isBlank())
            existing.setIdpSigningCertificate(dto.getIdpSigningCertificate());
        if (dto.getNameIdFormat() != null)           existing.setNameIdFormat(dto.getNameIdFormat());
        if (dto.getEmailAttribute() != null)         existing.setEmailAttribute(dto.getEmailAttribute());
        if (dto.getNameAttribute() != null)          existing.setNameAttribute(dto.getNameAttribute());
        if (dto.getWantAssertionsSigned() != null)   existing.setWantAssertionsSigned(dto.getWantAssertionsSigned());
        if (dto.getWantAuthnRequestSigned() != null) existing.setWantAuthnRequestSigned(dto.getWantAuthnRequestSigned());
        if (dto.getEnabled() != null)                existing.setEnabled(dto.getEnabled());

        auditService.recordAdmin(AuditEventTypes.SAML_PROVIDER_UPSERT, currentActor(),
                AuditEventTypes.TARGET_SAML_PROVIDER, String.valueOf(existing.getId()),
                AuditService.meta("tenant", tenant.getSlug(), "providerKey", existing.getProviderKey(), "created", false));
        return toDto(existing, tenant.getSlug(), true);
    }

    @Transactional
    public void delete(Long tenantId, String providerKey) {
        tenantAccessor.requireTenantAdmin();
        Tenant tenant = tenantRepository.findById(tenantId)
                .orElseThrow(() -> new EntityNotFoundException("Tenant " + tenantId + " not found"));
        tenantAccessor.requireSameTenant(tenant.getId());
        samlRepository.findByTenantIdAndProviderKey(tenantId, providerKey)
                .ifPresent(row -> {
                    samlRepository.delete(row);
                    auditService.recordAdmin(AuditEventTypes.SAML_PROVIDER_DELETE, currentActor(),
                            AuditEventTypes.TARGET_SAML_PROVIDER, String.valueOf(row.getId()),
                            AuditService.meta("tenant", tenant.getSlug(), "providerKey", providerKey));
                });
    }

    private User currentActor() {
        String tenantSlug = tech.cwvermaak.weldforge.config.tenant.TenantContext.get();
        var auth = org.springframework.security.core.context.SecurityContextHolder.getContext().getAuthentication();
        if (tenantSlug == null || auth == null || !(auth.getPrincipal() instanceof String email)) return null;
        return userRepository.findByTenant_SlugAndEmailIgnoreCase(tenantSlug, email).orElse(null);
    }

    /** Public discovery for the login page — scrubs sensitive fields. */
    public List<SamlProviderDto> listEnabledForSlug(String slug) {
        Tenant t = tenantRepository.findBySlug(slug)
                .orElseThrow(() -> new EntityNotFoundException("Tenant " + slug + " not found"));
        return samlRepository.findByTenantIdAndEnabledTrue(t.getId()).stream()
                .map(p -> toDto(p, t.getSlug(), false))
                .toList();
    }

    // -- Mapping -------------------------------------------------------

    private static SamlProviderDto toDto(TenantSamlProvider p, String tenantSlug, boolean includeAdminFields) {
        String registrationId = tenantSlug + "-saml-" + p.getProviderKey();
        SamlProviderDto d = SamlProviderDto.builder()
                .id(p.getId())
                .tenantId(p.getTenant().getId())
                .providerKey(p.getProviderKey())
                .displayName(p.getDisplayName())
                .ssoBinding(p.getSsoBinding())
                .nameIdFormat(p.getNameIdFormat())
                .enabled(p.getEnabled())
                .registrationId(registrationId)
                .loginUrl("/saml2/authenticate/" + registrationId)
                .spMetadataUrl("/saml2/service-provider-metadata/" + registrationId)
                .build();

        if (includeAdminFields) {
            d.setIdpEntityId(p.getIdpEntityId());
            d.setIdpSsoUrl(p.getIdpSsoUrl());
            d.setIdpSloUrl(p.getIdpSloUrl());
            d.setEmailAttribute(p.getEmailAttribute());
            d.setNameAttribute(p.getNameAttribute());
            d.setWantAssertionsSigned(p.getWantAssertionsSigned());
            d.setWantAuthnRequestSigned(p.getWantAuthnRequestSigned());
            // Certificate intentionally omitted from list responses — available
            // on demand via a separate GET if we ever add one.
        }
        return d;
    }

    private static String requireKey(String key) {
        if (key == null) throw new IllegalArgumentException("providerKey is required");
        String k = key.trim().toLowerCase();
        if (!PROVIDER_KEY_FORMAT.matcher(k).matches()) {
            throw new IllegalArgumentException(
                "providerKey must be lowercase alphanumeric + dashes, 2-64 chars");
        }
        return k;
    }

    private static void require(String v, String field) {
        if (v == null || v.isBlank()) throw new IllegalArgumentException(field + " is required");
    }
}
