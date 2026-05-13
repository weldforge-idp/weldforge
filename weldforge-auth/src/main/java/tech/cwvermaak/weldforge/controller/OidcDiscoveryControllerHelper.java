package tech.cwvermaak.weldforge.controller;

import jakarta.servlet.http.HttpServletRequest;
import tech.cwvermaak.weldforge.config.tenant.HostAliasFilter;

/**
 * Builds the canonical OIDC issuer URL for a tenant. Two shapes:
 *
 *   path-based   → "https://idp.weldforge.org/t/{slug}"  (default)
 *   host-aliased → "https://idp.writebuddy.org"          (when the host
 *                  was resolved via the tenant_hosts table by
 *                  {@link HostAliasFilter})
 */
final class OidcDiscoveryControllerHelper {

    private OidcDiscoveryControllerHelper() {}

    static String tenantIssuer(HttpServletRequest request, String slug) {
        String base = baseUrl(request);
        boolean hostAliased = request.getAttribute(HostAliasFilter.ATTR_HOST_ALIASED) != null;
        return hostAliased ? base : base + "/t/" + slug;
    }

    private static String baseUrl(HttpServletRequest request) {
        String scheme = request.getScheme();
        String host = request.getServerName();
        int port = request.getServerPort();
        boolean defaultPort = ("http".equals(scheme) && port == 80) || ("https".equals(scheme) && port == 443);
        return scheme + "://" + host + (defaultPort ? "" : ":" + port);
    }
}
