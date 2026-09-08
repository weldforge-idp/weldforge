package tech.cwvermaak.weldforge.controller;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import jakarta.persistence.EntityNotFoundException;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;
import tech.cwvermaak.weldforge.model.Tenant;
import tech.cwvermaak.weldforge.model.TenantSigningKey;
import tech.cwvermaak.weldforge.model.User;
import tech.cwvermaak.weldforge.repository.TenantRepository;
import tech.cwvermaak.weldforge.repository.UserRepository;
import tech.cwvermaak.weldforge.service.oidc.TenantSigningKeyService;

import tech.cwvermaak.weldforge.repository.RevokedOidcTokenRepository;
import tech.cwvermaak.weldforge.service.oidc.OidcIntrospectionService;

import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * OIDC userinfo endpoint. Verifies the bearer access token against the
 * tenant's published signing key, then returns claims from the user row.
 *
 * <p>Two rules govern what comes back (CONF-6.1). Claims correspond to the
 * scopes actually granted -- OIDC Core §5.4 -- so a token granted only
 * {@code openid} gets a subject and nothing else; previously every token got
 * the full profile regardless of what the user consented to. And the token is
 * checked against the revocation list, which introspection already consulted
 * and this endpoint did not, so a revoked token stopped working in one place
 * and kept working in the other.
 *
 * <p>Every 401 carries a {@code WWW-Authenticate} challenge (CONF-6.2, RFC 6750
 * §3). Without it a client cannot tell "your token expired, refresh it" from
 * "your request was malformed, do not retry", and the usual response to that
 * ambiguity is to bounce the user through a full login they did not need.
 */
@RestController
@RequiredArgsConstructor
public class OidcUserinfoController {

    private final TenantRepository tenantRepository;
    private final UserRepository userRepository;
    private final TenantSigningKeyService signingKeyService;
    private final RevokedOidcTokenRepository revocationRepository;

    @GetMapping("/t/{slug}/oauth2/userinfo")
    public ResponseEntity<Map<String, Object>> userinfo(@PathVariable String slug,
                                                        HttpServletRequest request) {
        Tenant tenant = tenantRepository.findBySlug(slug)
                .orElseThrow(() -> new EntityNotFoundException("Unknown tenant"));

        String header = request.getHeader("Authorization");
        if (header == null || !header.startsWith("Bearer ")) {
            // No credentials offered at all: RFC 6750 §3 says the challenge
            // carries no error code here, because nothing was wrong with a
            // token -- there wasn't one.
            return challenge(null, "Bearer token required");
        }
        String token = header.substring(7);

        Claims claims;
        try {
            // The key locator reads the kid from the JWS header and returns
            // the matching tenant public key, so a single parse both verifies
            // the signature and yields the claims.
            claims = Jwts.parser()
                    .keyLocator(jws -> {
                        TenantSigningKey row = signingKeyService.requireByKid(jws.get("kid").toString());
                        return signingKeyService.loadPublicKey(row);
                    })
                    .clockSkewSeconds(60)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();
        } catch (JwtException | IllegalArgumentException e) {
            return challenge("invalid_token", "The access token is malformed or its signature does not verify");
        }

        // The token must have been issued for *this* tenant.
        Object iss = claims.get("iss");
        if (iss == null || !iss.toString().endsWith("/t/" + tenant.getSlug())) {
            return challenge("invalid_token", "The access token was not issued for this tenant");
        }

        // B-OIDC-3: userinfo must be called with an ACCESS token (OIDC Core
        // §5.3.1). ID tokens are tenant-signed too but carry no token_type, so
        // reject anything that isn't explicitly an access token.
        if (!"access".equals(String.valueOf(claims.get("token_type")))) {
            return challenge("invalid_token", "An access token is required; an ID token is not accepted");
        }

        // CONF-6.1: introspection consulted the revocation list and this
        // endpoint did not, so a revoked token stopped working in one place and
        // kept working in the other for the remainder of its lifetime.
        if (revocationRepository.existsByTokenHash(OidcIntrospectionService.hash(token))) {
            return challenge("invalid_token", "The access token has been revoked");
        }

        Long userId;
        try {
            userId = Long.valueOf(claims.getSubject());
        } catch (NumberFormatException e) {
            return challenge("invalid_token", "The access token subject is not a user id");
        }
        User user = userRepository.findById(userId).orElse(null);
        if (user == null || !user.getTenant().getId().equals(tenant.getId())) {
            return challenge("invalid_token", "The access token subject is not a user of this tenant");
        }

        // CONF-6.1 / OIDC Core §5.4: the claims returned correspond to the
        // scopes actually granted. `sub` is unconditional -- it is what makes
        // the response a userinfo response at all.
        Set<String> scopes = scopesOf(claims);
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("sub", String.valueOf(user.getId()));
        if (scopes.contains("email")) {
            body.put("email", user.getEmail());
        }
        if (scopes.contains("profile")) {
            if (user.getName() != null) body.put("name", user.getName());
            if (user.getImageUrl() != null) body.put("picture", user.getImageUrl());
        }
        return ResponseEntity.ok(body);
    }

    /** The granted scopes carried on the access token, space-separated per RFC 6749. */
    private static Set<String> scopesOf(Claims claims) {
        Object scope = claims.get("scope");
        if (scope == null) return Set.of();
        List<String> parts = Arrays.stream(String.valueOf(scope).split("\\s+"))
                .filter(s -> !s.isBlank()).toList();
        return Set.copyOf(parts);
    }

    /**
     * A 401 carrying the {@code WWW-Authenticate} challenge RFC 6750 §3
     * requires (CONF-6.2).
     *
     * <p>The description is deliberately about the token's shape rather than
     * the account behind it: "not a user of this tenant" and "signature does
     * not verify" both say the token is unusable here without confirming
     * whether the subject exists, which would make this endpoint an
     * enumeration oracle.
     *
     * @param error an RFC 6750 error code, or null when no token was presented
     */
    private static ResponseEntity<Map<String, Object>> challenge(String error, String description) {
        StringBuilder value = new StringBuilder("Bearer realm=\"WeldForge\"");
        if (error != null) {
            value.append(", error=\"").append(error).append('"')
                 .append(", error_description=\"").append(description).append('"');
        }
        return ResponseEntity.status(401)
                .header(HttpHeaders.WWW_AUTHENTICATE, value.toString())
                .build();
    }
}
