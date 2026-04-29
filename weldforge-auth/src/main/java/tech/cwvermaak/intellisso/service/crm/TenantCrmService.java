package tech.cwvermaak.intellisso.service.crm;

import jakarta.persistence.EntityNotFoundException;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import tech.cwvermaak.intellisso.config.tenant.TenantAccessor;
import tech.cwvermaak.intellisso.model.Tenant;
import tech.cwvermaak.intellisso.model.TenantCrmProvider;
import tech.cwvermaak.intellisso.model.dto.CrmProviderDto;
import tech.cwvermaak.intellisso.repository.TenantCrmProviderRepository;
import tech.cwvermaak.intellisso.repository.TenantRepository;
import tech.cwvermaak.intellisso.service.audit.AuditEventTypes;
import tech.cwvermaak.intellisso.service.audit.AuditService;

import java.util.List;

/**
 * Admin CRUD for per-tenant CRM provider config (PRD §3.10). The
 * API token is write-only on the wire and encrypted at rest by the
 * entity's {@code @Convert} column.
 */
@Service
@RequiredArgsConstructor
public class TenantCrmService {

    private final TenantAccessor tenantAccessor;
    private final TenantRepository tenantRepository;
    private final TenantCrmProviderRepository repository;
    private final AuditService auditService;

    @Transactional(readOnly = true)
    public List<CrmProviderDto> list(Long tenantId) {
        tenantAccessor.requireAnyAdmin();
        assertAccess(tenantId);
        return repository.findByTenantId(tenantId).stream()
                .map(TenantCrmService::toMaskedDto)
                .toList();
    }

    @Transactional
    public CrmProviderDto create(Long tenantId, CrmProviderDto dto) {
        tenantAccessor.requireTenantAdmin();
        assertAccess(tenantId);
        validate(dto);
        Tenant tenant = tenantRepository.findById(tenantId)
                .orElseThrow(() -> new EntityNotFoundException("Tenant " + tenantId + " not found"));
        TenantCrmProvider provider = TenantCrmProvider.builder()
                .tenant(tenant)
                .name(dto.getName().trim())
                .providerType(dto.getProviderType())
                .baseUrl(dto.getBaseUrl().trim())
                .apiToken(dto.getApiToken())
                .fieldMappings(dto.getFieldMappings())
                .matchKeys(dto.getMatchKeys())
                .enabled(dto.getEnabled() == null || dto.getEnabled())
                .dedupeEnabled(dto.getDedupeEnabled() == null || dto.getDedupeEnabled())
                .build();
        TenantCrmProvider saved = repository.save(provider);

        auditService.recordAdmin(AuditEventTypes.CRM_PROVIDER_UPSERT, null,
                AuditEventTypes.TARGET_CRM_PROVIDER, String.valueOf(saved.getId()),
                AuditService.meta("type", saved.getProviderType().name(), "name", saved.getName()));
        return toMaskedDto(saved);
    }

    @Transactional
    public CrmProviderDto update(Long tenantId, Long id, CrmProviderDto dto) {
        tenantAccessor.requireTenantAdmin();
        assertAccess(tenantId);
        TenantCrmProvider provider = repository.findByIdAndTenantId(id, tenantId)
                .orElseThrow(() -> new EntityNotFoundException("CRM provider " + id + " not found"));

        if (dto.getName() != null) provider.setName(dto.getName().trim());
        if (dto.getProviderType() != null) provider.setProviderType(dto.getProviderType());
        if (dto.getBaseUrl() != null) provider.setBaseUrl(dto.getBaseUrl().trim());
        // Blank token means "leave existing" — avoid wiping on a partial PUT.
        if (dto.getApiToken() != null && !dto.getApiToken().isBlank()) {
            provider.setApiToken(dto.getApiToken());
        }
        if (dto.getFieldMappings() != null) provider.setFieldMappings(dto.getFieldMappings());
        if (dto.getMatchKeys() != null) provider.setMatchKeys(dto.getMatchKeys());
        if (dto.getEnabled() != null) provider.setEnabled(dto.getEnabled());
        if (dto.getDedupeEnabled() != null) provider.setDedupeEnabled(dto.getDedupeEnabled());

        auditService.recordAdmin(AuditEventTypes.CRM_PROVIDER_UPSERT, null,
                AuditEventTypes.TARGET_CRM_PROVIDER, String.valueOf(provider.getId()),
                AuditService.meta("name", provider.getName()));
        return toMaskedDto(provider);
    }

    @Transactional
    public void delete(Long tenantId, Long id) {
        tenantAccessor.requireTenantAdmin();
        assertAccess(tenantId);
        TenantCrmProvider provider = repository.findByIdAndTenantId(id, tenantId)
                .orElseThrow(() -> new EntityNotFoundException("CRM provider " + id + " not found"));
        repository.delete(provider);
        auditService.recordAdmin(AuditEventTypes.CRM_PROVIDER_DELETE, null,
                AuditEventTypes.TARGET_CRM_PROVIDER, String.valueOf(id),
                AuditService.meta("name", provider.getName()));
    }

    private void assertAccess(Long tenantId) {
        if (!tenantAccessor.isSuperAdmin()) {
            Long current = tenantAccessor.requireTenantId();
            if (!current.equals(tenantId)) {
                throw new AccessDeniedException("Cannot access another tenant's CRM providers");
            }
        }
    }

    private static void validate(CrmProviderDto dto) {
        if (dto.getName() == null || dto.getName().isBlank()) {
            throw new IllegalArgumentException("CRM provider name is required");
        }
        if (dto.getProviderType() == null) {
            throw new IllegalArgumentException("providerType is required");
        }
        if (dto.getBaseUrl() == null || dto.getBaseUrl().isBlank()) {
            throw new IllegalArgumentException("baseUrl is required");
        }
        if (dto.getApiToken() == null || dto.getApiToken().isBlank()) {
            throw new IllegalArgumentException("apiToken is required");
        }
        if (dto.getFieldMappings() == null || dto.getFieldMappings().isEmpty()) {
            throw new IllegalArgumentException("fieldMappings is required");
        }
    }

    private static CrmProviderDto toMaskedDto(TenantCrmProvider p) {
        return CrmProviderDto.builder()
                .id(p.getId())
                .tenantId(p.getTenant() != null ? p.getTenant().getId() : null)
                .name(p.getName())
                .providerType(p.getProviderType())
                .baseUrl(p.getBaseUrl())
                // apiToken is write-only — never echoed.
                .fieldMappings(p.getFieldMappings())
                .matchKeys(p.getMatchKeys())
                .enabled(p.isEnabled())
                .dedupeEnabled(p.isDedupeEnabled())
                .build();
    }
}
