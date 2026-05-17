package tech.cwvermaak.weldforge.config.tenant;

import tech.cwvermaak.weldforge.model.AdminRole;

/**
 * Per-request caller context: tenant slug + resolved tenant id + admin role.
 * Populated in order by the resolver filter (pre-auth defaults), the
 * app-key filter (machine-to-machine calls), and the JWT filter (end users).
 *
 * Every tenant-scoped repository query reads {@link #getTenantId()} to enforce
 * isolation, so it is critical that the value here is derived from
 * authenticated identity post-auth, never from client-supplied headers.
 */
public final class TenantContext {

    private static final ThreadLocal<String>    SLUG       = new ThreadLocal<>();
    private static final ThreadLocal<Long>      TENANT_ID  = new ThreadLocal<>();
    private static final ThreadLocal<AdminRole> ADMIN_ROLE = new ThreadLocal<>();

    // Authenticated principal identity — set by the auth filters, read by the
    // cross-tenant selector to resolve admin memberships. Exactly one of these
    // is non-null on an authenticated admin request.
    private static final ThreadLocal<Long> ACTOR_USER_ID            = new ThreadLocal<>();
    private static final ThreadLocal<Long> ACTOR_SERVICE_ACCOUNT_ID = new ThreadLocal<>();

    private TenantContext() {}

    public static void set(String slug) {
        SLUG.set(slug);
    }

    /** Back-compat — sets admin role based on the super-admin boolean. */
    public static void set(String slug, Long tenantId, boolean superAdmin) {
        set(slug, tenantId, superAdmin ? AdminRole.SUPER_ADMIN : AdminRole.NONE);
    }

    public static void set(String slug, Long tenantId, AdminRole adminRole) {
        SLUG.set(slug);
        TENANT_ID.set(tenantId);
        ADMIN_ROLE.set(adminRole != null ? adminRole : AdminRole.NONE);
    }

    public static String get() {
        return SLUG.get();
    }

    public static Long getTenantId() {
        return TENANT_ID.get();
    }

    public static AdminRole getAdminRole() {
        AdminRole r = ADMIN_ROLE.get();
        return r != null ? r : AdminRole.NONE;
    }

    public static boolean isSuperAdmin() {
        return getAdminRole() == AdminRole.SUPER_ADMIN;
    }

    /** Record the authenticated end user (JWT filter). */
    public static void setActorUser(Long userId) {
        ACTOR_USER_ID.set(userId);
    }

    /** Record the authenticated service account (app-authorization filter). */
    public static void setActorServiceAccount(Long serviceAccountId) {
        ACTOR_SERVICE_ACCOUNT_ID.set(serviceAccountId);
    }

    public static Long getActorUserId() {
        return ACTOR_USER_ID.get();
    }

    public static Long getActorServiceAccountId() {
        return ACTOR_SERVICE_ACCOUNT_ID.get();
    }

    public static void clear() {
        SLUG.remove();
        TENANT_ID.remove();
        ADMIN_ROLE.remove();
        ACTOR_USER_ID.remove();
        ACTOR_SERVICE_ACCOUNT_ID.remove();
    }
}
