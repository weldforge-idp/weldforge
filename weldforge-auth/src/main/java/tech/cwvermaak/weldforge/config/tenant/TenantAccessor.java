package tech.cwvermaak.weldforge.config.tenant;

import jakarta.persistence.EntityNotFoundException;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Component;
import tech.cwvermaak.weldforge.model.AdminMembership;
import tech.cwvermaak.weldforge.model.AdminRole;
import tech.cwvermaak.weldforge.model.Tenant;
import tech.cwvermaak.weldforge.repository.AdminMembershipRepository;
import tech.cwvermaak.weldforge.repository.TenantRepository;

/**
 * Central guard for tenant isolation. Services call {@link #requireTenantId()}
 * before any tenant-scoped query and {@link #requireSameTenant(Long)} before
 * mutating a row whose owning tenant was supplied from the request.
 *
 * Super admins bypass the {@link #requireSameTenant(Long)} check (that is the
 * whole reason the flag exists), but all other tenant-scoped listings still
 * use the caller's own tenant id unless the request explicitly selects a
 * different one via the {@code X-WF-Tenant} header, which {@link #switchToTenant(String)}
 * resolves against the caller's admin memberships.
 */
@Component
@RequiredArgsConstructor
public class TenantAccessor {

    private final TenantRepository tenantRepository;
    private final AdminMembershipRepository adminMembershipRepository;

    /** Current caller's tenant id — throws if the context is missing one. */
    public Long requireTenantId() {
        Long id = TenantContext.getTenantId();
        if (id != null) return id;

        // Fall back to slug lookup for pre-authenticated flows (login/register).
        String slug = TenantContext.get();
        if (slug == null) {
            throw new AccessDeniedException("No tenant in request context");
        }
        return tenantRepository.findBySlug(slug)
                .map(Tenant::getId)
                .orElseThrow(() -> new EntityNotFoundException("Unknown tenant: " + slug));
    }

    public Tenant requireTenant() {
        Long id = requireTenantId();
        return tenantRepository.findById(id)
                .orElseThrow(() -> new EntityNotFoundException("Tenant " + id + " not found"));
    }

    public boolean isSuperAdmin() {
        return TenantContext.isSuperAdmin();
    }

    public AdminRole adminRole() {
        return TenantContext.getAdminRole();
    }

    /**
     * Caller must be able to mutate admin resources within their tenant
     * (TENANT_ADMIN or SUPER_ADMIN). Throws {@link AccessDeniedException}
     * otherwise. PRD ADM-02.
     */
    public void requireTenantAdmin() {
        AdminRole r = adminRole();
        if (!r.canWriteTenant()) {
            throw new AccessDeniedException(
                    "Admin write access required — current role: " + r);
        }
    }

    /**
     * Caller must have at least read access to the admin console
     * (READ_ONLY, TENANT_ADMIN, or SUPER_ADMIN).
     */
    public void requireAnyAdmin() {
        AdminRole r = adminRole();
        if (!r.canRead()) {
            throw new AccessDeniedException(
                    "Admin read access required — current role: " + r);
        }
    }

    /**
     * Enforce that an incoming row id belongs to the caller's tenant (or the
     * caller is a super admin). Throws {@link AccessDeniedException} otherwise.
     */
    public void requireSameTenant(Long rowTenantId) {
        if (rowTenantId == null) {
            throw new AccessDeniedException("Row has no tenant");
        }
        if (isSuperAdmin()) return;
        Long mine = requireTenantId();
        if (!rowTenantId.equals(mine)) {
            throw new AccessDeniedException("Cross-tenant access denied");
        }
    }

    /**
     * The caller's effective admin role for {@code targetTenantId} — the
     * maximum of: the role resolved for their home tenant (when the target
     * IS the home tenant), any per-tenant admin membership for the target,
     * and any global membership. See {@code cross-tenant-admin-spec.md} §5.
     *
     * <p>Service accounts are not row-modelled: a {@code SUPER_ADMIN} token
     * is a platform-operator credential and reaches every tenant; a lesser
     * service account is confined to its home tenant.
     */
    public AdminRole effectiveRole(Long targetTenantId) {
        AdminRole role = AdminRole.NONE;

        // Home-tenant authority — the role the auth filter already resolved
        // (JWT 'adm' claim / service-account adminRole) applies when the
        // request targets the caller's own tenant. Keeps pre-membership
        // admins working unchanged (spec §8 back-compat).
        Long homeTenant = TenantContext.getTenantId();
        if (homeTenant != null && homeTenant.equals(targetTenantId)) {
            role = TenantContext.getAdminRole();
        }

        // Service account: a SUPER_ADMIN token reaches every tenant; anything
        // less stays scoped to the home tenant resolved above.
        if (TenantContext.getActorServiceAccountId() != null) {
            return TenantContext.getAdminRole() == AdminRole.SUPER_ADMIN
                    ? AdminRole.SUPER_ADMIN : role;
        }

        // End user: fold in admin_membership rows.
        Long actorUserId = TenantContext.getActorUserId();
        if (actorUserId != null) {
            for (AdminMembership m : adminMembershipRepository.findByUser_Id(actorUserId)) {
                if (m.isGlobal()) {
                    // Global rows are honoured as granted — SUPER_ADMIN included.
                    role = max(role, m.getAdminRole());
                } else if (m.getTenant() != null
                        && m.getTenant().getId().equals(targetTenantId)) {
                    // A per-tenant SUPER_ADMIN grant is downgraded to
                    // TENANT_ADMIN — SUPER_ADMIN is global-only (spec §5).
                    AdminRole granted = m.getAdminRole() == AdminRole.SUPER_ADMIN
                            ? AdminRole.TENANT_ADMIN : m.getAdminRole();
                    role = max(role, granted);
                }
            }
        }
        return role;
    }

    /**
     * Switch the request context to {@code targetSlug} for a cross-tenant
     * admin call — backs the {@code X-WF-Tenant} selector
     * ({@code cross-tenant-admin-spec.md} §6.1). Recomputes the caller's
     * admin role for the target via {@link #effectiveRole(Long)} and rebinds
     * {@link TenantContext}; the per-endpoint guards then enforce it.
     *
     * @throws EntityNotFoundException if the slug is unknown
     * @throws AccessDeniedException   if the caller has no admin reach there
     */
    public AdminRole switchToTenant(String targetSlug) {
        Tenant target = tenantRepository.findBySlug(targetSlug)
                .orElseThrow(() -> new EntityNotFoundException("Unknown tenant: " + targetSlug));
        AdminRole role = effectiveRole(target.getId());
        if (!role.canRead()) {
            throw new AccessDeniedException(
                    "Caller has no admin membership for tenant '" + targetSlug + "'");
        }
        // The actor-identity ThreadLocals are untouched by set(), so they survive.
        TenantContext.set(target.getSlug(), target.getId(), role);
        return role;
    }

    /** Higher of two roles by privilege: NONE &lt; READ_ONLY &lt; TENANT_ADMIN &lt; SUPER_ADMIN. */
    private static AdminRole max(AdminRole a, AdminRole b) {
        return a.ordinal() >= b.ordinal() ? a : b;
    }

    public void requireSuperAdmin() {
        if (!isSuperAdmin()) {
            throw new AccessDeniedException("Super admin only");
        }
    }
}
