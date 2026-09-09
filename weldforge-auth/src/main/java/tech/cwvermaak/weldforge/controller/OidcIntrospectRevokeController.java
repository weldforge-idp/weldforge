package tech.cwvermaak.weldforge.controller;

import jakarta.persistence.EntityNotFoundException;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import tech.cwvermaak.weldforge.model.OidcClient;
import tech.cwvermaak.weldforge.model.Tenant;
import tech.cwvermaak.weldforge.repository.OidcClientRepository;
import tech.cwvermaak.weldforge.repository.TenantRepository;
import tech.cwvermaak.weldforge.service.oidc.ClientCredentials;
import tech.cwvermaak.weldforge.service.oidc.OidcIntrospectionService;
import tech.cwvermaak.weldforge.service.oidc.OidcRevocationService;

import java.util.Map;

/**
 * Token introspection (RFC 7662) and revocation (RFC 7009).
 *
 * Both endpoints are tenant-scoped and authenticated by the calling
 * client's id + secret. Introspection is the cheap, predictable way for
 * resource servers to ask "is this access token still good?", and
 * revocation lets a relying party explicitly invalidate a token they
 * issued — combined, the two close out the OIDC contract.
 */
@RestController
@RequiredArgsConstructor
public class OidcIntrospectRevokeController {

    private final TenantRepository tenantRepository;
    private final OidcClientRepository clientRepository;
    private final OidcIntrospectionService introspectionService;
    private final OidcRevocationService revocationService;

    @PostMapping(value = "/t/{slug}/oauth2/introspect",
                 consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE,
                 produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Map<String, Object>> introspect(@PathVariable String slug,
                                                          @RequestParam("token") String token,
                                                          @RequestParam(value = "client_id", required = false) String clientId,
                                                          @RequestParam(value = "client_secret", required = false) String clientSecret,
                                                          @RequestParam(value = "token_type_hint", required = false) String tokenTypeHint,
                                                          HttpServletRequest request) {
        Tenant tenant = tenantRepository.findBySlug(slug)
                .orElseThrow(() -> new EntityNotFoundException("Unknown tenant"));

        // CONF-4.1: accept HTTP Basic here too. Introspection is called by
        // resource servers, which are the most likely of all callers to be a
        // stock library using the spec's preferred method.
        ClientCredentials credentials = ClientCredentials.resolve(request, clientId, clientSecret);
        clientId = credentials.clientId();
        clientSecret = credentials.clientSecret();

        // Authenticate the calling client. The introspection spec is
        // explicit: an unauthenticated request must be rejected, but
        // an authenticated one with a bogus token returns active=false
        // (NOT 401). That's so legitimate clients can call us safely.
        if (!verifyClient(tenant, clientId, clientSecret)) {
            return ResponseEntity.status(401).build();
        }

        String issuer = OidcDiscoveryControllerHelper.tenantIssuer(request, tenant.getSlug());
        // B-OIDC-3: scope the result to the authenticated caller's own tokens.
        return ResponseEntity.ok(introspectionService.introspect(token, tenant, issuer, clientId));
    }

    /**
     * RFC 7009 revocation.
     *
     * <p>{@code client_secret} is optional (CONF-6.3): a public client holds no
     * secret, so requiring one meant the clients most likely to need revocation
     * -- native and single-page apps, whose tokens live on devices that get lost
     * -- could not revoke anything at all. A public client authenticates by
     * {@code client_id}; a confidential one must still present its secret.
     *
     * <p>{@code token_type_hint} is accepted and ignored, which is what §2.1
     * asks for: it is a hint, and a server that trusted it would fail to revoke
     * a correctly-presented token that the client mislabelled. Both token types
     * are tried regardless.
     */
    @PostMapping(value = "/t/{slug}/oauth2/revoke",
                 consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    public ResponseEntity<Void> revoke(@PathVariable String slug,
                                       @RequestParam("token") String token,
                                       @RequestParam(value = "client_id", required = false) String clientId,
                                       @RequestParam(value = "client_secret", required = false) String clientSecret,
                                       @RequestParam(value = "token_type_hint", required = false) String tokenTypeHint,
                                       HttpServletRequest request) {
        Tenant tenant = tenantRepository.findBySlug(slug)
                .orElseThrow(() -> new EntityNotFoundException("Unknown tenant"));

        ClientCredentials credentials = ClientCredentials.resolve(request, clientId, clientSecret);
        clientId = credentials.clientId();
        clientSecret = credentials.clientSecret();

        OidcClient client = clientRepository.findByTenantIdAndClientId(tenant.getId(), clientId).orElse(null);
        if (client == null || !authenticatesAs(client, clientSecret)) {
            return ResponseEntity.status(401).build();
        }

        String issuer = OidcDiscoveryControllerHelper.tenantIssuer(request, tenant.getSlug());
        revocationService.revoke(token, tenant, client, issuer);
        // RFC 7009: always 200, even when the token was unknown.
        return ResponseEntity.ok().build();
    }

    private boolean verifyClient(Tenant tenant, String clientId, String clientSecret) {
        return clientRepository.findByTenantIdAndClientId(tenant.getId(), clientId)
                .map(c -> constantTimeEquals(clientSecret, c.getClientSecret()))
                .orElse(false);
    }

    /** Constant-time secret comparison — avoids a timing oracle on the client secret. */
    private static boolean constantTimeEquals(String a, String b) {
        if (a == null || b == null) return false;
        return java.security.MessageDigest.isEqual(
                a.getBytes(java.nio.charset.StandardCharsets.UTF_8),
                b.getBytes(java.nio.charset.StandardCharsets.UTF_8));
    }

    /**
     * Whether the presented credentials authenticate this client.
     *
     * <p>A public client has no secret to present, so possession of the
     * {@code client_id} is all there is -- the same position the token endpoint
     * already takes for a public client's code exchange, where PKCE rather than
     * a secret is what proves the caller. A confidential client must present
     * its secret, compared in constant time.
     */
    private static boolean authenticatesAs(OidcClient client, String clientSecret) {
        if (client.isPublicClient()) {
            return true;
        }
        return constantTimeEquals(clientSecret, client.getClientSecret());
    }
}
