package tech.cwvermaak.weldforge.service.crm;

import tech.cwvermaak.weldforge.model.TenantCrmProvider;

import java.util.Map;

/**
 * Thin seam over the HTTP transport used by CRM provisioners. The
 * production implementation is backed by {@link java.net.http.HttpClient}
 * and runs every call through the {@code crm} circuit breaker (PRD AVL-04);
 * the BDD layer swaps in a map-based fake that records each upsert for
 * assertion.
 */
public interface CrmClient {

    /** Outcome of a single upsert. */
    record Result(boolean success, String externalId, int statusCode, String error) {}

    /**
     * Upsert a contact/lead record in the target CRM. When {@code
     * existingExternalId} is non-null the implementation should update
     * that record; otherwise it should create a new one and return the
     * newly-minted id. Field naming conventions differ by CRM; the
     * {@code fields} map is already in the shape {@link CrmProvisioningService}
     * derived from the provider's field mappings.
     */
    Result upsert(TenantCrmProvider provider,
                  String existingExternalId,
                  Map<String, Object> fields);
}
