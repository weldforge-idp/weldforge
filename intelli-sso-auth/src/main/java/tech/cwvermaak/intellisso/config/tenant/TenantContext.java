package tech.cwvermaak.intellisso.config.tenant;

/**
 * Per-request caller context: tenant slug + resolved tenant id + super-admin
 * flag. Populated in order by the resolver filter (pre-auth defaults), the
 * app-key filter (machine-to-machine calls), and the JWT filter (end users).
 *
 * Every tenant-scoped repository query reads {@link #getTenantId()} to enforce
 * isolation, so it is critical that the value here is derived from
 * authenticated identity post-auth, never from client-supplied headers.
 */
public final class TenantContext {

    private static final ThreadLocal<String>  SLUG      = new ThreadLocal<>();
    private static final ThreadLocal<Long>    TENANT_ID = new ThreadLocal<>();
    private static final ThreadLocal<Boolean> SUPER     = new ThreadLocal<>();

    private TenantContext() {}

    public static void set(String slug) {
        SLUG.set(slug);
    }

    public static void set(String slug, Long tenantId, boolean superAdmin) {
        SLUG.set(slug);
        TENANT_ID.set(tenantId);
        SUPER.set(superAdmin);
    }

    public static String get() {
        return SLUG.get();
    }

    public static Long getTenantId() {
        return TENANT_ID.get();
    }

    public static boolean isSuperAdmin() {
        Boolean v = SUPER.get();
        return v != null && v;
    }

    public static void clear() {
        SLUG.remove();
        TENANT_ID.remove();
        SUPER.remove();
    }
}
