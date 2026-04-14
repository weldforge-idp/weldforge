package tech.cwvermaak.intellisso.service;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.Map;

@Service
public class JwtService {

    public static final String CLAIM_TENANT_ID    = "tid";
    public static final String CLAIM_TENANT_SLUG  = "tenant";
    public static final String CLAIM_SUPER_ADMIN  = "sa";
    public static final String CLAIM_PURPOSE      = "purpose";
    public static final String CLAIM_TOKEN_VERSION = "ver";
    public static final String PURPOSE_MFA_CHALLENGE = "mfa_challenge";
    public static final String PURPOSE_ACCESS       = "access";

    private static final long MFA_CHALLENGE_TTL_MS = 5 * 60 * 1000L;

    @Value("${app.jwt.secret}")
    private String secret;

    @Value("${app.jwt.access-token-expiration-ms}")
    private long accessExpirationMs;

    @Value("${app.jwt.refresh-token-expiration-ms:604800000}")
    private long refreshExpirationMs;

    private SecretKey getSigningKey() {
        byte[] keyBytes = secret.getBytes(StandardCharsets.UTF_8);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    public String generateAccessToken(String email, Long tenantId, String tenantSlug,
                                      boolean superAdmin, int tokenVersion) {
        return generateAccessToken(email, tenantId, tenantSlug, superAdmin, tokenVersion, null, null);
    }

    /**
     * Extended overload — PRD SSO-03 + OA2-07.
     *
     * @param tenantTtlMs  per-tenant TTL override in milliseconds, or null
     *                     to use the application default
     * @param customClaims per-tenant custom claims to inject (OA2-07); null
     *                     or empty means none. Any collision with a reserved
     *                     claim name is ignored.
     */
    public String generateAccessToken(String email, Long tenantId, String tenantSlug,
                                      boolean superAdmin, int tokenVersion,
                                      Long tenantTtlMs, Map<String, Object> customClaims) {
        Map<String, Object> claims = new LinkedHashMap<>();
        // Custom claims go first so reserved claims below always win on collision.
        if (customClaims != null) {
            for (Map.Entry<String, Object> e : customClaims.entrySet()) {
                if (!isReservedClaim(e.getKey())) {
                    claims.put(e.getKey(), e.getValue());
                }
            }
        }
        claims.put(CLAIM_TENANT_ID, tenantId);
        claims.put(CLAIM_TENANT_SLUG, tenantSlug == null ? "" : tenantSlug);
        claims.put(CLAIM_SUPER_ADMIN, superAdmin);
        claims.put(CLAIM_PURPOSE, PURPOSE_ACCESS);
        claims.put(CLAIM_TOKEN_VERSION, tokenVersion);

        long ttl = tenantTtlMs != null && tenantTtlMs > 0 ? tenantTtlMs : accessExpirationMs;
        return Jwts.builder()
                .subject(email)
                .claims(claims)
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + ttl))
                .signWith(getSigningKey())
                .compact();
    }

    private static boolean isReservedClaim(String name) {
        return switch (name) {
            case "sub", "iss", "aud", "exp", "iat", "nbf", "jti",
                 CLAIM_TENANT_ID, CLAIM_TENANT_SLUG, CLAIM_SUPER_ADMIN,
                 CLAIM_PURPOSE, CLAIM_TOKEN_VERSION -> true;
            default -> false;
        };
    }

    /** Back-compat overload used in tests that don't care about version. */
    public String generateAccessToken(String email, Long tenantId, String tenantSlug, boolean superAdmin) {
        return generateAccessToken(email, tenantId, tenantSlug, superAdmin, 0);
    }

    public Integer extractTokenVersion(io.jsonwebtoken.Claims claims) {
        Object v = claims.get(CLAIM_TOKEN_VERSION);
        if (v instanceof Number n) return n.intValue();
        if (v instanceof String s && !s.isBlank()) {
            try { return Integer.valueOf(s); } catch (NumberFormatException ignored) {}
        }
        return null;
    }

    /**
     * Short-lived token issued after password auth succeeds but before MFA
     * has been satisfied. Carries just enough identity to look up the user
     * on the second step, and a {@code purpose=mfa_challenge} claim so it
     * cannot be substituted for an access token.
     */
    public String generateMfaChallengeToken(Long userId, Long tenantId, String tenantSlug) {
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put(CLAIM_TENANT_ID, tenantId);
        claims.put(CLAIM_TENANT_SLUG, tenantSlug == null ? "" : tenantSlug);
        claims.put(CLAIM_PURPOSE, PURPOSE_MFA_CHALLENGE);
        return Jwts.builder()
                .subject(String.valueOf(userId))
                .claims(claims)
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + MFA_CHALLENGE_TTL_MS))
                .signWith(getSigningKey())
                .compact();
    }

    public boolean isMfaChallenge(io.jsonwebtoken.Claims claims) {
        Object p = claims.get(CLAIM_PURPOSE);
        return PURPOSE_MFA_CHALLENGE.equals(p == null ? null : p.toString());
    }

    public String generateRefreshToken(String email, Long tenantId) {
        return Jwts.builder()
                .subject(email)
                .claim(CLAIM_TENANT_ID, tenantId)
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + refreshExpirationMs))
                .signWith(getSigningKey())
                .compact();
    }

    public Claims parse(String token) {
        return Jwts.parser()
                .verifyWith(getSigningKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    public String extractEmail(String token) { return parse(token).getSubject(); }

    public Long extractTenantId(String token) {
        Object v = parse(token).get(CLAIM_TENANT_ID);
        if (v instanceof Number n) return n.longValue();
        if (v instanceof String s && !s.isBlank()) return Long.valueOf(s);
        return null;
    }

    public boolean isTokenValid(String token) {
        try { parse(token); return true; }
        catch (JwtException | IllegalArgumentException e) { return false; }
    }

    public long getExpirationTime() { return accessExpirationMs / 1000; }
    public long getRefreshTokenExpirationTime() { return refreshExpirationMs / 1000; }
}
