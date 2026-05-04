package tech.cwvermaak.weldforge.service.ldap;

import jakarta.persistence.EntityNotFoundException;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import tech.cwvermaak.weldforge.config.tenant.TenantAccessor;
import tech.cwvermaak.weldforge.model.LdapProviderType;
import tech.cwvermaak.weldforge.model.Tenant;
import tech.cwvermaak.weldforge.model.TenantLdapProvider;
import tech.cwvermaak.weldforge.model.dto.LdapProviderDto;
import tech.cwvermaak.weldforge.repository.TenantLdapProviderRepository;
import tech.cwvermaak.weldforge.repository.TenantRepository;
import tech.cwvermaak.weldforge.service.audit.AuditEventTypes;
import tech.cwvermaak.weldforge.service.audit.AuditService;

import java.util.List;

/**
 * Admin CRUD for per-tenant LDAP/AD providers (PRD DIR-01, DIR-02).
 * Tenant-isolated via {@link TenantAccessor}; the service account
 * password is encrypted at rest and never echoed on reads.
 */
@Service
@RequiredArgsConstructor
public class TenantLdapService {

    private final TenantAccessor tenantAccessor;
    private final TenantRepository tenantRepository;
    private final TenantLdapProviderRepository repository;
    private final LdapUpstreamService ldapUpstreamService;
    private final AuditService auditService;

    @Transactional(readOnly = true)
    public List<LdapProviderDto> list(Long tenantId) {
        tenantAccessor.requireAnyAdmin();
        assertAccess(tenantId);
        return repository.findByTenantId(tenantId).stream()
                .map(TenantLdapService::toMaskedDto)
                .toList();
    }

    @Transactional
    public LdapProviderDto create(Long tenantId, LdapProviderDto dto) {
        tenantAccessor.requireTenantAdmin();
        assertAccess(tenantId);
        validate(dto);
        Tenant tenant = tenantRepository.findById(tenantId)
                .orElseThrow(() -> new EntityNotFoundException("Tenant " + tenantId + " not found"));

        TenantLdapProvider provider = TenantLdapProvider.builder()
                .tenant(tenant)
                .name(dto.getName().trim())
                .providerType(dto.getProviderType() == null ? LdapProviderType.LDAP : dto.getProviderType())
                .url(dto.getUrl().trim())
                .bindDn(dto.getBindDn())
                .bindPassword(dto.getBindPassword())
                .userBaseDn(dto.getUserBaseDn().trim())
                .userSearchFilter(nonBlankOr(dto.getUserSearchFilter(), "(uid={0})"))
                .emailAttribute(nonBlankOr(dto.getEmailAttribute(), "mail"))
                .nameAttribute(nonBlankOr(dto.getNameAttribute(), "cn"))
                .usernameAttribute(nonBlankOr(dto.getUsernameAttribute(), "uid"))
                .startTls(Boolean.TRUE.equals(dto.getStartTls()))
                .connectTimeoutMs(dto.getConnectTimeoutMs() == null ? 5000 : dto.getConnectTimeoutMs())
                .readTimeoutMs(dto.getReadTimeoutMs() == null ? 10000 : dto.getReadTimeoutMs())
                .enabled(dto.getEnabled() == null || dto.getEnabled())
                .build();

        TenantLdapProvider saved = repository.save(provider);
        auditService.recordAdmin(AuditEventTypes.LDAP_PROVIDER_UPSERT, null,
                AuditEventTypes.TARGET_LDAP_PROVIDER, String.valueOf(saved.getId()),
                AuditService.meta("name", saved.getName(), "type", saved.getProviderType().name()));
        return toMaskedDto(saved);
    }

    @Transactional
    public LdapProviderDto update(Long tenantId, Long id, LdapProviderDto dto) {
        tenantAccessor.requireTenantAdmin();
        assertAccess(tenantId);
        TenantLdapProvider provider = repository.findByIdAndTenantId(id, tenantId)
                .orElseThrow(() -> new EntityNotFoundException("LDAP provider " + id + " not found"));

        if (dto.getName() != null) provider.setName(dto.getName().trim());
        if (dto.getProviderType() != null) provider.setProviderType(dto.getProviderType());
        if (dto.getUrl() != null) provider.setUrl(dto.getUrl().trim());
        if (dto.getBindDn() != null) provider.setBindDn(dto.getBindDn());
        // A blank password means "leave it as-is" — the DTO is write-only
        // so an empty string from a PUT that didn't touch the field
        // would otherwise wipe the stored credential.
        if (dto.getBindPassword() != null && !dto.getBindPassword().isEmpty()) {
            provider.setBindPassword(dto.getBindPassword());
        }
        if (dto.getUserBaseDn() != null) provider.setUserBaseDn(dto.getUserBaseDn().trim());
        if (dto.getUserSearchFilter() != null) provider.setUserSearchFilter(dto.getUserSearchFilter());
        if (dto.getEmailAttribute() != null) provider.setEmailAttribute(dto.getEmailAttribute());
        if (dto.getNameAttribute() != null) provider.setNameAttribute(dto.getNameAttribute());
        if (dto.getUsernameAttribute() != null) provider.setUsernameAttribute(dto.getUsernameAttribute());
        if (dto.getStartTls() != null) provider.setStartTls(dto.getStartTls());
        if (dto.getConnectTimeoutMs() != null) provider.setConnectTimeoutMs(dto.getConnectTimeoutMs());
        if (dto.getReadTimeoutMs() != null) provider.setReadTimeoutMs(dto.getReadTimeoutMs());
        if (dto.getEnabled() != null) provider.setEnabled(dto.getEnabled());

        auditService.recordAdmin(AuditEventTypes.LDAP_PROVIDER_UPSERT, null,
                AuditEventTypes.TARGET_LDAP_PROVIDER, String.valueOf(provider.getId()),
                AuditService.meta("name", provider.getName()));
        return toMaskedDto(provider);
    }

    @Transactional
    public void delete(Long tenantId, Long id) {
        tenantAccessor.requireTenantAdmin();
        assertAccess(tenantId);
        TenantLdapProvider provider = repository.findByIdAndTenantId(id, tenantId)
                .orElseThrow(() -> new EntityNotFoundException("LDAP provider " + id + " not found"));
        repository.delete(provider);
        auditService.recordAdmin(AuditEventTypes.LDAP_PROVIDER_DELETE, null,
                AuditEventTypes.TARGET_LDAP_PROVIDER, String.valueOf(id),
                AuditService.meta("name", provider.getName()));
    }

    /** Verify a provider's bind credentials without hitting a user account. */
    @Transactional(readOnly = true)
    public boolean testConnection(Long tenantId, Long id) {
        tenantAccessor.requireTenantAdmin();
        assertAccess(tenantId);
        TenantLdapProvider provider = repository.findByIdAndTenantId(id, tenantId)
                .orElseThrow(() -> new EntityNotFoundException("LDAP provider " + id + " not found"));
        return ldapUpstreamService.testConnection(provider);
    }

    // ---- Helpers ---------------------------------------------------

    private void assertAccess(Long tenantId) {
        if (!tenantAccessor.isSuperAdmin()) {
            Long current = tenantAccessor.requireTenantId();
            if (!current.equals(tenantId)) {
                throw new AccessDeniedException("Cannot access another tenant's LDAP providers");
            }
        }
    }

    private static void validate(LdapProviderDto dto) {
        if (dto.getName() == null || dto.getName().isBlank()) {
            throw new IllegalArgumentException("LDAP provider name is required");
        }
        if (dto.getUrl() == null || dto.getUrl().isBlank()) {
            throw new IllegalArgumentException("LDAP url is required");
        }
        if (dto.getUserBaseDn() == null || dto.getUserBaseDn().isBlank()) {
            throw new IllegalArgumentException("userBaseDn is required");
        }
    }

    private static String nonBlankOr(String value, String fallback) {
        return value == null || value.isBlank() ? fallback : value;
    }

    private static LdapProviderDto toMaskedDto(TenantLdapProvider p) {
        return LdapProviderDto.builder()
                .id(p.getId())
                .tenantId(p.getTenant() != null ? p.getTenant().getId() : null)
                .name(p.getName())
                .providerType(p.getProviderType())
                .url(p.getUrl())
                .bindDn(p.getBindDn())
                // bindPassword is write-only — never echoed.
                .userBaseDn(p.getUserBaseDn())
                .userSearchFilter(p.getUserSearchFilter())
                .emailAttribute(p.getEmailAttribute())
                .nameAttribute(p.getNameAttribute())
                .usernameAttribute(p.getUsernameAttribute())
                .startTls(p.isStartTls())
                .connectTimeoutMs(p.getConnectTimeoutMs())
                .readTimeoutMs(p.getReadTimeoutMs())
                .enabled(p.isEnabled())
                .build();
    }
}
