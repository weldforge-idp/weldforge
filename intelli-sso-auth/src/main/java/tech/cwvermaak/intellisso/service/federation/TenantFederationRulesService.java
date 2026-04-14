package tech.cwvermaak.intellisso.service.federation;

import jakarta.persistence.EntityNotFoundException;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import tech.cwvermaak.intellisso.config.tenant.TenantAccessor;
import tech.cwvermaak.intellisso.model.Tenant;
import tech.cwvermaak.intellisso.model.dto.FederationRulesDto;
import tech.cwvermaak.intellisso.repository.TenantRepository;
import tech.cwvermaak.intellisso.service.audit.AuditEventTypes;
import tech.cwvermaak.intellisso.service.audit.AuditService;

/**
 * Admin-facing CRUD for per-tenant federation rules (PRD FED-02, FED-04).
 * Tenant isolation is enforced by {@link TenantAccessor}: a TENANT_ADMIN
 * can only edit their own tenant; SUPER_ADMIN may edit any.
 */
@Service
@RequiredArgsConstructor
public class TenantFederationRulesService {

    private final TenantAccessor tenantAccessor;
    private final TenantRepository tenantRepository;
    private final AuditService auditService;

    @Transactional(readOnly = true)
    public FederationRulesDto get(Long tenantId) {
        tenantAccessor.requireAnyAdmin();
        Tenant tenant = loadAuthorised(tenantId);
        return FederationRulesDto.builder()
                .matchingRules(tenant.getMatchingRules())
                .claimTransforms(tenant.getClaimTransforms())
                .build();
    }

    @Transactional
    public FederationRulesDto upsert(Long tenantId, FederationRulesDto dto) {
        tenantAccessor.requireTenantAdmin();
        Tenant tenant = loadAuthorised(tenantId);
        tenant.setMatchingRules(dto.getMatchingRules());
        tenant.setClaimTransforms(dto.getClaimTransforms());
        tenantRepository.save(tenant);

        auditService.recordAdmin(AuditEventTypes.FEDERATION_RULES_UPDATE, null,
                AuditEventTypes.TARGET_TENANT, String.valueOf(tenant.getId()),
                AuditService.meta(
                        "matching_rules_count",
                        dto.getMatchingRules() == null ? 0 : dto.getMatchingRules().size(),
                        "claim_transforms_count",
                        dto.getClaimTransforms() == null ? 0 : dto.getClaimTransforms().size()));

        return FederationRulesDto.builder()
                .matchingRules(tenant.getMatchingRules())
                .claimTransforms(tenant.getClaimTransforms())
                .build();
    }

    private Tenant loadAuthorised(Long tenantId) {
        // Tenant admins can only touch their own tenant; super admins can touch any.
        if (!tenantAccessor.isSuperAdmin()) {
            Long current = tenantAccessor.requireTenantId();
            if (!current.equals(tenantId)) {
                throw new org.springframework.security.access.AccessDeniedException(
                        "Cannot edit federation rules for another tenant");
            }
        }
        return tenantRepository.findById(tenantId)
                .orElseThrow(() -> new EntityNotFoundException("Tenant " + tenantId + " not found"));
    }
}
