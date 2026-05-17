package tech.cwvermaak.weldforge.model;

/**
 * Admin-console authorization role. Orthogonal to {@link Role} (which is
 * the tenant's own application-level RBAC). PRD ADM-02.
 */
public enum AdminRole {

    /** No admin console access at all. Default for new users. */
    NONE,

    /** Read-only access to the admin console for their own tenant. */
    READ_ONLY,

    /**
     * Full management access to their own tenant — users, roles, OIDC
     * clients, SAML providers, MFA policy, Twilio config, audit log.
     * Cannot create, delete, or inspect other tenants.
     */
    TENANT_ADMIN,

    /**
     * Platform-wide administration. Meaningful only as a GLOBAL admin
     * membership ({@code admin_membership} with {@code tenant_id = NULL}) or
     * on a {@code SUPER_ADMIN} service-account token — it then applies to
     * every tenant, present and future. Required for creating/deleting
     * tenants and granting admin memberships. A per-tenant {@code SUPER_ADMIN}
     * grant is downgraded to {@link #TENANT_ADMIN} — see
     * {@code docs/cross-tenant-admin-spec.md} section 5.
     */
    SUPER_ADMIN;

    /** True when this role may at least read the admin console. */
    public boolean canRead() {
        return this == READ_ONLY || this == TENANT_ADMIN || this == SUPER_ADMIN;
    }

    /** True when this role may write within its own tenant. */
    public boolean canWriteTenant() {
        return this == TENANT_ADMIN || this == SUPER_ADMIN;
    }
}
