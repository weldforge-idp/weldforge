package tech.cwvermaak.weldforge.service;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * How a client's branding overlays its tenant's.
 *
 * <p>Key by key, not wholesale. A client that wants its own logo on the
 * tenant's palette should set one key, not restate the palette — and setting
 * one key must not blank the rest, which is what replacing the whole object
 * would do.
 *
 * <p>A one-line function with a test, rather than a conditional inside a
 * service, because "which branding wins" is a question people will ask of
 * this system and it should have one readable answer.
 */
public final class BrandingMerge {

    private BrandingMerge() {
    }

    /**
     * Tenant branding with the client's keys laid over it.
     *
     * @param tenant the tenant's branding, or null
     * @param client the client's branding, or null to inherit entirely
     * @return a new map; never null, possibly empty
     */
    public static Map<String, Object> merge(Map<String, Object> tenant, Map<String, Object> client) {
        Map<String, Object> out = new LinkedHashMap<>();
        if (tenant != null) out.putAll(tenant);
        if (client == null) return out;

        for (Map.Entry<String, Object> e : client.entrySet()) {
            Object v = e.getValue();
            // A null or blank value means "say nothing", not "clear the
            // tenant's". Clearing is expressed by setting the key to the
            // value you want, and a client that wants no logo at all is a
            // case nobody has asked for -- whereas a half-filled client
            // record blanking a tenant's palette is a case that would happen
            // on the first save.
            if (v == null) continue;
            if (v instanceof String s && s.isBlank()) continue;
            out.put(e.getKey(), v);
        }
        return out;
    }
}
