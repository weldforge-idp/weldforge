package tech.cwvermaak.intellisso.controller;

import jakarta.servlet.http.HttpServletRequest;

/** Tiny helper that builds the canonical issuer URL for a tenant. */
final class OidcDiscoveryControllerHelper {

    private OidcDiscoveryControllerHelper() {}

    static String tenantIssuer(HttpServletRequest request, String slug) {
        String scheme = request.getScheme();
        String host = request.getServerName();
        int port = request.getServerPort();
        boolean defaultPort = ("http".equals(scheme) && port == 80) || ("https".equals(scheme) && port == 443);
        String base = scheme + "://" + host + (defaultPort ? "" : ":" + port);
        return base + "/t/" + slug;
    }
}
