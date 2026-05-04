package tech.cwvermaak.weldforge.config.tenant;

import jakarta.persistence.EntityNotFoundException;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Component;
import tech.cwvermaak.weldforge.model.AdminRole;
import tech.cwvermaak.weldforge.model.Tenant;
import tech.cwvermaak.weldforge.repository.TenantRepository;

/**
 * Central guard for tenant isolation. Services call {@link #requireTenantId()}
 * before any tenant-scoped query and {@link #requireSameTenant(Long)} before
 * mutating a row whose owning tenant was supplied from the request.
 *
 * Super admins bypass the {@link #requireSameTenant(Long)} check (that is the
 * whole reason the flag exists), but all other tenant-scoped listings still
 * use the caller's own tenant id unless an endpoint explicitly resolves a
 * different one via {@link #resolveCrossTenant(Long)}.
 */
@Component
@RequiredArgsConstructor
public class TenantAccessor {

    private final TenantRepository tenantRepository;

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
     * Resolve a tenant by id for an endpoint that may legitimately operate on
     * a different tenant (super admin only). Regular callers are forced to
     * their own tenant regardless of the requested id.
     */
    public Tenant resolveCrossTenant(Long requestedTenantId) {
        if (isSuperAdmin() && requestedTenantId != null) {
            return tenantRepository.findById(requestedTenantId)
                    .orElseThrow(() -> new EntityNotFoundException("Tenant " + requestedTenantId + " not found"));
        }
        return requireTenant();
    }

    public void requireSuperAdmin() {
        if (!isSuperAdmin()) {
            throw new AccessDeniedException("Super admin only");
        }
    }
}
