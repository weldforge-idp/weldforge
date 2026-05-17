package tech.cwvermaak.weldforge.service;

import jakarta.persistence.EntityNotFoundException;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import tech.cwvermaak.weldforge.config.tenant.TenantAccessor;
import tech.cwvermaak.weldforge.config.tenant.TenantContext;
import tech.cwvermaak.weldforge.model.AdminMembership;
import tech.cwvermaak.weldforge.model.AdminRole;
import tech.cwvermaak.weldforge.model.AuditEvent;
import tech.cwvermaak.weldforge.model.Tenant;
import tech.cwvermaak.weldforge.model.User;
import tech.cwvermaak.weldforge.model.dto.AdminMembershipDto;
import tech.cwvermaak.weldforge.repository.AdminMembershipRepository;
import tech.cwvermaak.weldforge.repository.TenantRepository;
import tech.cwvermaak.weldforge.repository.UserRepository;
import tech.cwvermaak.weldforge.service.audit.AuditEventTypes;
import tech.cwvermaak.weldforge.service.audit.AuditService;

import java.util.List;
import java.util.Objects;

/**
 * Manage admin memberships — cross-tenant-admin-spec.md §6.2 (phase 4).
 *
 * <p>An admin membership grants a user admin authority over a tenant, or —
 * when the tenant is null — over every tenant (a global membership).
 * Granting and revoking are gated on <b>global {@code SUPER_ADMIN}</b>
 * scope: a tenant-scoped admin can never mint cross-tenant or global grants,
 * so the API cannot be used to escalate privilege. {@code SUPER_ADMIN} is
 * only valid as a global membership (spec §5).
 */
@Service
@RequiredArgsConstructor
public class AdminMembershipService {

    private final TenantAccessor tenantAccessor;
    private final AdminMembershipRepository membershipRepository;
    private final UserRepository userRepository;
    private final TenantRepository tenantRepository;
    private final AuditService auditService;

    @Transactional(readOnly = true)
    public List<AdminMembershipDto> list(Long userId) {
        tenantAccessor.requireGlobalSuperAdmin();
        User user = requireUser(userId);
        return membershipRepository.findByUser_Id(user.getId()).stream()
                .map(AdminMembershipService::toDto)
                .toList();
    }

    /**
     * Grant (or, for an existing (user, tenant) pair, update) an admin
     * membership. {@code dto.tenantId == null} grants a global membership.
     */
    @Transactional
    public AdminMembershipDto grant(Long userId, AdminMembershipDto dto) {
        tenantAccessor.requireGlobalSuperAdmin();
        User user = requireUser(userId);

        AdminRole role = dto.getAdminRole();
        if (role == null || role == AdminRole.NONE) {
            throw new IllegalArgumentException(
                    "adminRole must be READ_ONLY, TENANT_ADMIN or SUPER_ADMIN");
        }

        Tenant tenant = null;
        if (dto.getTenantId() != null) {
            tenant = tenantRepository.findById(dto.getTenantId())
                    .orElseThrow(() -> new EntityNotFoundException(
                            "Tenant " + dto.getTenantId() + " not found"));
            // Spec §5: SUPER_ADMIN is only meaningful as a global membership.
            if (role == AdminRole.SUPER_ADMIN) {
                throw new IllegalArgumentException(
                        "SUPER_ADMIN is only valid as a global membership — omit tenantId");
            }
        }
        Long tenantId = tenant != null ? tenant.getId() : null;

        // One membership per (user, tenant): re-granting updates the role.
        AdminMembership membership = membershipRepository.findByUser_Id(user.getId()).stream()
                .filter(m -> Objects.equals(
                        m.getTenant() != null ? m.getTenant().getId() : null, tenantId))
                .findFirst()
                .orElse(null);
        if (membership != null) {
            membership.setAdminRole(role);
        } else {
            membership = AdminMembership.builder()
                    .user(user)
                    .tenant(tenant)
                    .adminRole(role)
                    .grantedBy(TenantContext.getActorUserId())
                    .build();
        }
        membership = membershipRepository.save(membership);

        audit(AuditEventTypes.ADMIN_MEMBERSHIP_GRANT, user, membership,
                tenant == null ? "global" : tenant.getSlug());
        return toDto(membership);
    }

    @Transactional
    public void revoke(Long userId, Long membershipId) {
        tenantAccessor.requireGlobalSuperAdmin();
        AdminMembership membership = membershipRepository.findByIdAndUser_Id(membershipId, userId)
                .orElseThrow(() -> new EntityNotFoundException(
                        "Membership " + membershipId + " not found for user " + userId));
        String scope = membership.getTenant() == null
                ? "global" : membership.getTenant().getSlug();
        membershipRepository.delete(membership);
        audit(AuditEventTypes.ADMIN_MEMBERSHIP_REVOKE, membership.getUser(), membership, scope);
    }

    // ---- helpers -----------------------------------------------------

    private User requireUser(Long userId) {
        return userRepository.findById(userId)
                .orElseThrow(() -> new EntityNotFoundException("User " + userId + " not found"));
    }

    private void audit(String eventType, User target, AdminMembership membership, String scope) {
        auditService.log(AuditEvent.builder()
                .eventType(eventType)
                .outcome(AuditEvent.Outcome.SUCCESS)
                .tenant(membership.getTenant())   // null for a global membership
                .targetType(AuditEventTypes.TARGET_USER)
                .targetId(String.valueOf(target.getId()))
                .metadata(AuditService.meta(
                        "target_email", target.getEmail(),
                        "scope", scope,
                        "admin_role", membership.getAdminRole().name(),
                        "granted_by", String.valueOf(TenantContext.getActorUserId()))));
    }

    static AdminMembershipDto toDto(AdminMembership m) {
        return AdminMembershipDto.builder()
                .id(m.getId())
                .userId(m.getUser().getId())
                .tenantId(m.getTenant() != null ? m.getTenant().getId() : null)
                .tenantSlug(m.getTenant() != null ? m.getTenant().getSlug() : null)
                .adminRole(m.getAdminRole())
                .grantedBy(m.getGrantedBy())
                .grantedAt(m.getGrantedAt())
                .build();
    }
}
