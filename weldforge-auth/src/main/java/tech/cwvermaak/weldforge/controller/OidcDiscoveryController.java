package tech.cwvermaak.weldforge.controller;

import jakarta.persistence.EntityNotFoundException;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;
import tech.cwvermaak.weldforge.model.Tenant;
import tech.cwvermaak.weldforge.repository.TenantRepository;
import tech.cwvermaak.weldforge.service.oidc.OidcAuthorizationService;
import tech.cwvermaak.weldforge.service.oidc.TenantSigningKeyService;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * OIDC discovery + JWKS for a tenant. Both endpoints are public — they
 * have to be, downstream relying parties hit them before they have any
 * credentials.
 *
 * The {@code issuer} value embedded in the discovery document is the
 * canonical URL of the tenant's OIDC namespace. Tokens minted for this
 * tenant carry the same value as their {@code iss} claim, so verifiers
 * that resolve the issuer URL get back the matching JWKS.
 */
@RestController
@RequiredArgsConstructor
public class OidcDiscoveryController {

    /** @see OidcRegistrationController#register */
    @org.springframework.beans.factory.annotation.Value(
            "${app.security.oidc.dynamic-registration-enabled:false}")
    private boolean dynamicRegistrationEnabled;

    private final TenantRepository tenantRepository;
    private final TenantSigningKeyService signingKeyService;
    private final tech.cwvermaak.weldforge.service.oidc.OidcScopeService scopeService;

    /**
     * The three URLs an OAuth client may build from a path-bearing issuer.
     *
     * <p>Our tenant issuer carries a path -- {@code https://host/t/{slug}} -- and
     * RFC 8414 §3.1, its §5 compatibility notes, and the Model Context Protocol's
     * discovery rules all say the same thing about that case: a client inserts the
     * well-known segment BEFORE the issuer's path and only falls back to appending
     * it. The order tried is oauth-authorization-server with path insertion, then
     * openid-configuration with path insertion, then openid-configuration appended.
     *
     * <p>Only the third existed here. The other two were not 404s, which would at
     * least have let a client fall through: everything outside {@code /api},
     * {@code /t/}, {@code /saml2}, {@code /scim} and {@code /health} is routed to
     * the admin portal, so both answered <b>200 with an HTML page</b>. A careful
     * client parses it, fails, and moves on; a strict one stops at the first 200 and
     * never reaches the document that exists. Verified against production on
     * 2026-10-12. It is the same shape as the {@code /actuator} and
     * {@code /api/auth/**} traps already on record: a 200 from this estate is not
     * evidence that an endpoint exists.
     *
     * <p><b>The ingress must route {@code /.well-known/} to this service</b> or these
     * two mappings are unreachable and nothing changes. That is a change in the
     * infrastructure repository.
     *
     * <p>One builder behind all three, because the {@code issuer} they publish has to
     * be byte-identical -- a client MUST reject a document whose issuer differs from
     * the one it used to build the URL (RFC 8414 §3.3), so drift between these would
     * not degrade, it would fail.
     *
     * <p>RFC 8414 permits additional metadata parameters, so the OIDC-specific
     * members below are legitimate in the oauth-authorization-server document and
     * one document can serve both.
     */
    @GetMapping({
            "/t/{slug}/.well-known/openid-configuration",
            "/.well-known/openid-configuration/t/{slug}",
            "/.well-known/oauth-authorization-server/t/{slug}",
    })
    public ResponseEntity<Map<String, Object>> discovery(@PathVariable String slug,
                                                         HttpServletRequest request) {
        Tenant tenant = lookupTenant(slug);
        String issuer = baseUrl(request) + "/t/" + tenant.getSlug();

        Map<String, Object> doc = new LinkedHashMap<>();
        doc.put("issuer", issuer);
        doc.put("authorization_endpoint", issuer + "/oauth2/authorize");
        doc.put("token_endpoint",         issuer + "/oauth2/token");
        doc.put("userinfo_endpoint",      issuer + "/oauth2/userinfo");
        doc.put("jwks_uri",               issuer + "/oauth2/jwks");
        doc.put("introspection_endpoint", issuer + "/oauth2/introspect");
        doc.put("revocation_endpoint",    issuer + "/oauth2/revoke");
        doc.put("end_session_endpoint",   issuer + "/oauth2/logout");
        // CONF-4.2: the point of discovery is capability detection, so the
        // document has to describe what the server actually does. It listed
        // neither the refresh_token grant nor the registration endpoint, both
        // of which are implemented and reachable -- a client that trusted the
        // document concluded neither existed.
        // Advertised only when the deployment actually accepts it. It was
        // published unconditionally while the endpoint answered 403 to every
        // caller it exists for -- the same untruth as scopes_supported, and
        // the kind a client library believes.
        if (dynamicRegistrationEnabled) {
            doc.put("registration_endpoint", issuer + "/oauth2/register");
        }
        doc.put("response_types_supported",  List.of("code"));
        doc.put("response_modes_supported",  List.of("query"));
        doc.put("grant_types_supported",
                List.of("authorization_code", "refresh_token", "client_credentials"));
        doc.put("subject_types_supported",   List.of("public"));
        doc.put("id_token_signing_alg_values_supported", List.of("RS256"));
        doc.put("token_endpoint_auth_methods_supported",
                List.of("client_secret_basic", "client_secret_post", "none"));
        // Must match what the server actually accepts. OidcAuthorizationService
        // permits every standard OIDC scope regardless of client registration,
        // so advertising a subset is a lie in the direction that breaks
        // integrations quietly: a conformant client library validates the
        // scope it wants against this list and refuses to ask for one that is
        // missing, even though the request would have succeeded.
        //
        // offline_access is the one that bites. It is how an RP asks for a
        // refresh token in OIDC, and omitting it here sent at least one
        // integrator looking for a server-side switch that does not exist.
        // The standard OIDC scopes plus whatever this tenant has registered.
        // Advertising only the standard six was the same untruth the rest of
        // this document was fixed for: a conformant client validates the scope
        // it wants against this list and refuses to ask for one that is
        // missing, so a tenant's own scopes were unreachable through any
        // library that checks.
        java.util.List<String> scopes = new java.util.ArrayList<>(
                OidcAuthorizationService.standardScopes());
        for (String registered : scopeService.registeredNames(tenant.getId())) {
            if (!scopes.contains(registered)) scopes.add(registered);
        }
        doc.put("scopes_supported", scopes);
        doc.put("code_challenge_methods_supported", List.of("S256"));
        // Claims the issuer actually mints, rather than a subset of them.
        // auth_time has been minted since CONF-2.2 (Sprint 4) and was never
        // listed here; an RP doing capability detection concluded it was
        // absent -- the CONF-4.2 failure in miniature.
        doc.put("claims_supported", List.of(
                "sub", "iss", "aud", "exp", "iat", "auth_time", "email", "name", "picture",
                "nonce", "amr", "roles"));
        // CONF-1.4 / RFC 9207: advertised so a client knows it can rely on the
        // parameter being present, which is what lets it treat a response
        // WITHOUT one as suspicious.
        doc.put("authorization_response_iss_parameter_supported", true);
        return ResponseEntity.ok(doc);
    }

    @GetMapping("/t/{slug}/oauth2/jwks")
    public ResponseEntity<Map<String, Object>> jwks(@PathVariable String slug) {
        Tenant tenant = lookupTenant(slug);
        return ResponseEntity.ok(signingKeyService.jwks(tenant));
    }

    private Tenant lookupTenant(String slug) {
        return tenantRepository.findBySlug(slug)
                .orElseThrow(() -> new EntityNotFoundException("Unknown tenant: " + slug));
    }

    private static String baseUrl(HttpServletRequest request) {
        String scheme = request.getScheme();
        String host = request.getServerName();
        int port = request.getServerPort();
        boolean defaultPort = ("http".equals(scheme) && port == 80) || ("https".equals(scheme) && port == 443);
        return scheme + "://" + host + (defaultPort ? "" : ":" + port);
    }
}
