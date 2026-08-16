package tech.cwvermaak.weldforge.service.oidc;

import io.jsonwebtoken.Jwts;
import io.micrometer.core.instrument.MeterRegistry;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import tech.cwvermaak.weldforge.model.OidcClient;
import tech.cwvermaak.weldforge.model.Tenant;
import tech.cwvermaak.weldforge.model.TenantSigningKey;
import tech.cwvermaak.weldforge.model.User;

import java.security.interfaces.RSAPrivateKey;
import java.time.Instant;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Mints RS256-signed access tokens and ID tokens using the tenant's
 * private key. The {@code kid} from {@link TenantSigningKey} is set in the
 * JWS header so verifiers can pick the matching key from the tenant's
 * JWKS endpoint.
 *
 * Multi-tenancy is enforced by construction: the only way to get a key
 * for tenant A is to ask {@link TenantSigningKeyService} for it, and the
 * issued token's {@code iss} claim contains the tenant's discovery URL,
 * so a token issued for one tenant cannot be replayed against another.
 */
@Service
@RequiredArgsConstructor
public class OidcTokenService {

    /** Access token lifetime in seconds. Configurable via {@code app.oidc.access-token-seconds}. */
    @Value("${app.oidc.access-token-seconds:3600}")
    private long accessTokenSeconds;

    /** ID token lifetime in seconds. */
    @Value("${app.oidc.id-token-seconds:3600}")
    private long idTokenSeconds;

    private final TenantSigningKeyService signingKeyService;
    private final MeterRegistry meterRegistry;

    /**
     * Issue an access token + ID token pair for a successful authorization
     * code exchange. The {@code nonce} from the original /authorize request
     * is mirrored into the ID token per the OIDC spec.
     */
    public IssuedTokens issueForCodeExchange(Tenant tenant, OidcClient client, User user,
                                             List<String> scopes, String nonce, String issuer) {
        TenantSigningKey key = signingKeyService.getOrCreateActive(tenant);
        RSAPrivateKey privateKey = signingKeyService.loadPrivateKey(key);
        Instant now = Instant.now();

        long tenantTtlSeconds = resolveAccessTtlSeconds(tenant);
        Map<String, Object> tenantClaims = tenant.getCustomClaims();
        String accessToken = buildAccessToken(client, user, scopes, issuer, key.getKid(), privateKey, now,
                tenantTtlSeconds, tenantClaims);
        String idToken     = buildIdToken(client, user, nonce, issuer, key.getKid(), privateKey, now,
                tenantTtlSeconds, tenantClaims);

        meterRegistry.counter("sso.token.issued", "grant_type", "authorization_code",
                "tenant", tenant.getSlug()).increment();
        return new IssuedTokens(accessToken, idToken, tenantTtlSeconds);
    }

    public IssuedTokens issueForClientCredentials(Tenant tenant, OidcClient client, List<String> scopes, String issuer) {
        TenantSigningKey key = signingKeyService.getOrCreateActive(tenant);
        RSAPrivateKey privateKey = signingKeyService.loadPrivateKey(key);
        Instant now = Instant.now();
        meterRegistry.counter("sso.token.issued", "grant_type", "client_credentials",
                "tenant", tenant.getSlug()).increment();
        long tenantTtlSeconds = resolveAccessTtlSeconds(tenant);
        String accessToken = buildAccessToken(client, null, scopes, issuer, key.getKid(), privateKey, now,
                tenantTtlSeconds, tenant.getCustomClaims());
        // No ID token in the client_credentials grant; expiresIn carries the
        // *resolved* per-tenant TTL so the response doesn't lie (B-OIDC-5).
        return new IssuedTokens(accessToken, null, tenantTtlSeconds);
    }

    /** PRD SSO-03: per-tenant access TTL takes precedence over the OIDC default. */
    private long resolveAccessTtlSeconds(Tenant tenant) {
        if (tenant.getAccessTtlMs() != null && tenant.getAccessTtlMs() > 0) {
            return tenant.getAccessTtlMs() / 1000;
        }
        return accessTokenSeconds;
    }

    private String buildAccessToken(OidcClient client, User user, List<String> scopes,
                                    String issuer, String kid, RSAPrivateKey privateKey, Instant now,
                                    long ttlSeconds, Map<String, Object> tenantCustomClaims) {
        Map<String, Object> claims = new LinkedHashMap<>();
        // Per-tenant custom claims go in first so the reserved claims below
        // always win on collision (OA2-07).
        if (tenantCustomClaims != null) {
            for (Map.Entry<String, Object> e : tenantCustomClaims.entrySet()) {
                if (!isReservedOidcClaim(e.getKey())) {
                    claims.put(e.getKey(), e.getValue());
                }
            }
        }
        claims.put("iss", issuer);
        claims.put("aud", client.getClientId());
        claims.put("client_id", client.getClientId());
        claims.put("scope", String.join(" ", scopes));
        claims.put("token_type", "access");
        if (user != null) {
            claims.put("sub", String.valueOf(user.getId()));
            claims.put("email", user.getEmail());
            if (user.getName() != null) claims.put("name", user.getName());
            // Tenant-scoped role propagation: relying parties read this claim
            // to drive their own RBAC (e.g. Spring Security's
            // hasRole('SUPERADMIN')). Emitted as an array so users can grow
            // multiple roles in future without breaking the contract. The
            // is_super_admin boolean is collapsed into the same array as
            // "SUPERADMIN" so apps need only one check.
            claims.put("roles", rolesFor(user));
        } else {
            // Client credentials grant — there's no end-user.
            claims.put("sub", client.getClientId());
        }
        return Jwts.builder()
                .header().keyId(kid).and()
                .claims(claims)
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plusSeconds(ttlSeconds)))
                .signWith(privateKey, Jwts.SIG.RS256)
                .compact();
    }

    private String buildIdToken(OidcClient client, User user, String nonce,
                                String issuer, String kid, RSAPrivateKey privateKey, Instant now,
                                long ttlSeconds, Map<String, Object> tenantCustomClaims) {
        Map<String, Object> claims = new LinkedHashMap<>();
        if (tenantCustomClaims != null) {
            for (Map.Entry<String, Object> e : tenantCustomClaims.entrySet()) {
                if (!isReservedOidcClaim(e.getKey())) {
                    claims.put(e.getKey(), e.getValue());
                }
            }
        }
        claims.put("iss", issuer);
        claims.put("aud", client.getClientId());
        claims.put("sub", String.valueOf(user.getId()));
        claims.put("email", user.getEmail());
        if (user.getName() != null) claims.put("name", user.getName());
        claims.put("roles", rolesFor(user));
        if (nonce != null && !nonce.isBlank()) claims.put("nonce", nonce);
        return Jwts.builder()
                .header().keyId(kid).and()
                .claims(claims)
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plusSeconds(Math.min(ttlSeconds, idTokenSeconds))))
                .signWith(privateKey, Jwts.SIG.RS256)
                .compact();
    }

    private static boolean isReservedOidcClaim(String name) {
        return switch (name) {
            case "iss", "aud", "sub", "exp", "iat", "nbf", "jti",
                 "client_id", "scope", "token_type", "email", "name", "nonce", "roles" -> true;
            default -> false;
        };
    }

    /**
     * Collapses {@link User#getRole()} (the tenant-scoped application role —
     * e.g. {@code SUPERADMIN}, {@code SITE_ADMIN}) and the legacy
     * {@link User#isSuperAdmin()} boolean into a single deduplicated list
     * relying parties can drive RBAC from. Always returns at least an
     * empty list so consumers don't have to null-check.
     */
    private static List<String> rolesFor(User user) {
        java.util.LinkedHashSet<String> out = new java.util.LinkedHashSet<>();
        if (user.isSuperAdmin()) out.add("SUPERADMIN");
        if (user.getRole() != null && user.getRole().getName() != null
                && !user.getRole().getName().isBlank()) {
            out.add(user.getRole().getName());
        }
        return new java.util.ArrayList<>(out);
    }

    public record IssuedTokens(String accessToken, String idToken, long expiresIn) {}
}
