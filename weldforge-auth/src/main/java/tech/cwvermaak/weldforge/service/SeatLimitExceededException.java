package tech.cwvermaak.weldforge.service;

/**
 * Thrown when creating a user would take a tenant past its
 * {@code max_users} seat cap. Mapped to HTTP 409 by
 * {@code GlobalExceptionHandler} — the request is well-formed, it conflicts
 * with the tenant's current state.
 *
 * <p>Carries the limit and the current count so callers can render an
 * actionable message rather than a bare refusal. The message is safe to show
 * a tenant administrator; it leaks nothing beyond their own tenant's size.
 */
public class SeatLimitExceededException extends RuntimeException {

    private final String tenantSlug;
    private final int limit;
    private final long current;

    public SeatLimitExceededException(String tenantSlug, int limit, long current) {
        super("Tenant '" + tenantSlug + "' has reached its limit of " + limit
                + " active users (" + current + " in use). Deactivate an existing "
                + "user to free a seat, or upgrade the plan.");
        this.tenantSlug = tenantSlug;
        this.limit = limit;
        this.current = current;
    }

    public String getTenantSlug() { return tenantSlug; }

    public int getLimit() { return limit; }

    public long getCurrent() { return current; }
}
