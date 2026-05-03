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
     * Unrestricted access across every tenant. Required for creating or
     * deleting tenants and for assigning admin roles.
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

    /** True for SUPER_ADMIN only. */
    public boolean canCrossTenants() {
        return this == SUPER_ADMIN;
    }
}
