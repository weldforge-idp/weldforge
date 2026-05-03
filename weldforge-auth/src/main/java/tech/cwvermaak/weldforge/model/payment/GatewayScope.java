package tech.cwvermaak.weldforge.model.payment;

/**
 * Ownership scope of a {@code payment_gateways} row.
 *
 * <ul>
 *   <li>{@link #PLATFORM} — gateway credentials belong to WeldForge
 *       itself, used to charge subscribers for paid tiers. {@code
 *       tenant_id} is NULL.</li>
 *   <li>{@link #TENANT} — credentials belong to a tenant, used when
 *       that tenant bills its own end-users via the broker endpoints.
 *       {@code tenant_id} is NOT NULL.</li>
 * </ul>
 *
 * The {@code pg_scope_tenant_coherent} DB check constraint enforces
 * the relationship between scope and {@code tenant_id}.
 */
public enum GatewayScope {
    PLATFORM,
    TENANT
}
