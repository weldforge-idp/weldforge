package tech.cwvermaak.weldforge.service.oidc;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import tech.cwvermaak.weldforge.model.Tenant;
import tech.cwvermaak.weldforge.model.TenantSigningKey;
import tech.cwvermaak.weldforge.repository.RevokedOidcTokenRepository;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * RFC 7662 token introspection. Resource servers POST a token they
 * received from a client and we tell them whether it's currently active
 * + return the standard set of claims so they don't have to parse it
 * themselves.
 *
 * Active means all of:
 *   - The signature verifies against one of the tenant's published keys
 *   - The token is not in the revocation list
 *   - The token has not expired
 *   - The {@code iss} claim matches the tenant URL the resource server
 *     is asking about (so a token from tenant A can't be introspected
 *     against tenant B and report active)
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class OidcIntrospectionService {

    public static final Map<String, Object> INACTIVE = Map.of("active", false);

    private final TenantSigningKeyService signingKeyService;
    private final RevokedOidcTokenRepository revocationRepository;

    public Map<String, Object> introspect(String token, Tenant tenant, String tenantIssuer) {
        if (token == null || token.isBlank()) return INACTIVE;

        // The introspection contract returns active=false for any
        // unknown / malformed / expired / revoked token rather than
        // raising an error — clients depend on it never throwing.
        Claims claims;
        try {
            claims = Jwts.parser()
                    .keyLocator(jws -> {
                        String kid = jws.get("kid").toString();
                        TenantSigningKey row = signingKeyService.requireByKid(kid);
                        if (!row.getTenant().getId().equals(tenant.getId())) {
                            throw new IllegalStateException("kid belongs to a different tenant");
                        }
                        return signingKeyService.loadPublicKey(row);
                    })
                    .clockSkewSeconds(60)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();
        } catch (JwtException | IllegalStateException | IllegalArgumentException e) {
            log.debug("Introspection rejected token: {}", e.getMessage());
            return INACTIVE;
        }

        Object iss = claims.get("iss");
        if (iss == null || !tenantIssuer.equals(iss.toString())) {
            return INACTIVE;
        }

        if (revocationRepository.existsByTokenHash(hash(token))) {
            return INACTIVE;
        }

        long now = System.currentTimeMillis() / 1000L;
        if (claims.getExpiration() != null
                && claims.getExpiration().getTime() / 1000L <= now) {
            return INACTIVE;
        }

        Map<String, Object> response = new LinkedHashMap<>();
        response.put("active",    true);
        response.put("sub",       claims.getSubject());
        response.put("iss",       iss);
        response.put("client_id", claims.get("client_id"));
        response.put("scope",     claims.get("scope"));
        response.put("token_type", "Bearer");
        if (claims.getExpiration() != null) {
            response.put("exp", claims.getExpiration().getTime() / 1000L);
        }
        if (claims.getIssuedAt() != null) {
            response.put("iat", claims.getIssuedAt().getTime() / 1000L);
        }
        Object aud = claims.get("aud");
        if (aud != null) response.put("aud", aud);
        Object email = claims.get("email");
        if (email != null) response.put("email", email);
        return response;
    }

    /** Hashes are produced with the same scheme as the revocation service. */
    static String hash(String token) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            return Base64.getUrlEncoder().withoutPadding()
                    .encodeToString(md.digest(token.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    @SuppressWarnings("unused")
    private static Collection<?> coerceCollection(Object o) {
        return o instanceof Collection<?> c ? c : null;
    }
}
