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

    private final TenantRepository tenantRepository;
    private final TenantSigningKeyService signingKeyService;

    @GetMapping("/t/{slug}/.well-known/openid-configuration")
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
        doc.put("registration_endpoint",  issuer + "/oauth2/register");
        doc.put("response_types_supported",  List.of("code"));
        doc.put("response_modes_supported",  List.of("query"));
        doc.put("grant_types_supported",
                List.of("authorization_code", "refresh_token", "client_credentials"));
        doc.put("subject_types_supported",   List.of("public"));
        doc.put("id_token_signing_alg_values_supported", List.of("RS256"));
        doc.put("token_endpoint_auth_methods_supported",
                List.of("client_secret_basic", "client_secret_post", "none"));
        doc.put("scopes_supported", List.of("openid", "profile", "email"));
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
