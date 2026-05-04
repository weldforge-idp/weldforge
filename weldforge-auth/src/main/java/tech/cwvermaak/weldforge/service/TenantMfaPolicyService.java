package tech.cwvermaak.weldforge.service;

import jakarta.persistence.EntityNotFoundException;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import tech.cwvermaak.weldforge.config.tenant.TenantAccessor;
import tech.cwvermaak.weldforge.model.Tenant;
import tech.cwvermaak.weldforge.model.TenantMfaPolicy;
import tech.cwvermaak.weldforge.model.User;
import tech.cwvermaak.weldforge.model.dto.MfaPolicyDto;
import tech.cwvermaak.weldforge.repository.MfaFactorRepository;
import tech.cwvermaak.weldforge.repository.TenantMfaPolicyRepository;
import tech.cwvermaak.weldforge.repository.TenantRepository;
import tech.cwvermaak.weldforge.repository.UserRepository;
import tech.cwvermaak.weldforge.service.audit.AuditEventTypes;
import tech.cwvermaak.weldforge.service.audit.AuditService;

import java.time.Duration;
import java.time.LocalDateTime;

/**
 * Manages the per-tenant MFA enforcement policy and answers runtime
 * enforcement questions for {@code AuthService} and
 * {@code OidcAuthorizationService}.
 *
 * <p>Policy semantics:
 * <ul>
 *   <li>OPTIONAL — users may enroll, login always succeeds.</li>
 *   <li>REQUIRED — login returns {@code mustEnrollMfa=true} if the user
 *       has no verified factor AND the grace period since account
 *       creation has elapsed.</li>
 *   <li>RISK_ADAPTIVE — reserved; treated as OPTIONAL at runtime until
 *       risk signals are wired up.</li>
 * </ul>
 */
@Service
@RequiredArgsConstructor
public class TenantMfaPolicyService {

    private final TenantAccessor tenantAccessor;
    private final TenantRepository tenantRepository;
    private final TenantMfaPolicyRepository policyRepository;
    private final MfaFactorRepository mfaFactorRepository;
    private final UserRepository userRepository;
    private final AuditService auditService;

    // ---- Admin CRUD --------------------------------------------------

    public MfaPolicyDto get(Long tenantId) {
        tenantAccessor.requireAnyAdmin();
        Tenant t = tenantRepository.findById(tenantId)
                .orElseThrow(() -> new EntityNotFoundException("Tenant " + tenantId + " not found"));
        tenantAccessor.requireSameTenant(t.getId());
        return policyRepository.findByTenantId(tenantId)
                .map(TenantMfaPolicyService::toDto)
                .orElse(defaultDto(tenantId));
    }

    @Transactional
    public MfaPolicyDto upsert(Long tenantId, MfaPolicyDto dto) {
        tenantAccessor.requireTenantAdmin();
        Tenant tenant = tenantRepository.findById(tenantId)
                .orElseThrow(() -> new EntityNotFoundException("Tenant " + tenantId + " not found"));
        tenantAccessor.requireSameTenant(tenant.getId());

        TenantMfaPolicy policy = policyRepository.findByTenantId(tenantId).orElse(null);
        boolean created = false;
        if (policy == null) {
            policy = TenantMfaPolicy.builder()
                    .tenant(tenant)
                    .enforcement(TenantMfaPolicy.Enforcement.OPTIONAL)
                    .gracePeriodDays(7)
                    .defaultStepupMaxAge(0)
                    .build();
            created = true;
        }

        if (dto.getEnforcement() != null) policy.setEnforcement(dto.getEnforcement());
        if (dto.getGracePeriodDays() != null && dto.getGracePeriodDays() >= 0) {
            policy.setGracePeriodDays(dto.getGracePeriodDays());
        }
        if (dto.getDefaultStepupMaxAge() != null && dto.getDefaultStepupMaxAge() >= 0) {
            policy.setDefaultStepupMaxAge(dto.getDefaultStepupMaxAge());
        }

        policy = policyRepository.save(policy);

        auditService.recordAdmin(AuditEventTypes.MFA_POLICY_UPSERT, currentActor(),
                AuditEventTypes.TARGET_MFA_POLICY, String.valueOf(policy.getId()),
                AuditService.meta(
                        "tenant", tenant.getSlug(),
                        "enforcement", policy.getEnforcement().name(),
                        "grace_days", policy.getGracePeriodDays(),
                        "stepup_max_age", policy.getDefaultStepupMaxAge(),
                        "created", created));

        return toDto(policy);
    }

    // ---- Runtime enforcement -----------------------------------------

    /** The effective policy for a tenant — absence = OPTIONAL default. */
    public TenantMfaPolicy effectivePolicy(Long tenantId) {
        return policyRepository.findByTenantId(tenantId).orElseGet(() ->
                TenantMfaPolicy.builder()
                        .enforcement(TenantMfaPolicy.Enforcement.OPTIONAL)
                        .gracePeriodDays(7)
                        .defaultStepupMaxAge(0)
                        .build());
    }

    /**
     * True if {@code user} must enroll an MFA factor before they can
     * continue. Called by {@code AuthService.login} after password
     * verification.
     */
    public boolean mustEnroll(User user) {
        if (user == null || user.getTenant() == null) return false;
        TenantMfaPolicy policy = effectivePolicy(user.getTenant().getId());
        if (policy.getEnforcement() != TenantMfaPolicy.Enforcement.REQUIRED) return false;

        // Grace period: users whose account is newer than N days still get a pass.
        LocalDateTime createdAt = user.getCreatedAt();
        if (createdAt != null && policy.getGracePeriodDays() != null
                && policy.getGracePeriodDays() > 0) {
            Duration age = Duration.between(createdAt, LocalDateTime.now());
            if (age.toDays() < policy.getGracePeriodDays()) return false;
        }

        return mfaFactorRepository.findByUserIdAndEnabledTrueAndVerifiedTrue(user.getId()).isEmpty();
    }

    // ---- Helpers -----------------------------------------------------

    private User currentActor() {
        String slug = tech.cwvermaak.weldforge.config.tenant.TenantContext.get();
        var auth = org.springframework.security.core.context.SecurityContextHolder.getContext().getAuthentication();
        if (slug == null || auth == null || !(auth.getPrincipal() instanceof String email)) return null;
        return userRepository.findByTenant_SlugAndEmailIgnoreCase(slug, email).orElse(null);
    }

    static MfaPolicyDto toDto(TenantMfaPolicy p) {
        return MfaPolicyDto.builder()
                .id(p.getId())
                .tenantId(p.getTenant() != null ? p.getTenant().getId() : null)
                .enforcement(p.getEnforcement())
                .gracePeriodDays(p.getGracePeriodDays())
                .defaultStepupMaxAge(p.getDefaultStepupMaxAge())
                .build();
    }

    private static MfaPolicyDto defaultDto(Long tenantId) {
        return MfaPolicyDto.builder()
                .tenantId(tenantId)
                .enforcement(TenantMfaPolicy.Enforcement.OPTIONAL)
                .gracePeriodDays(7)
                .defaultStepupMaxAge(0)
                .build();
    }
}
