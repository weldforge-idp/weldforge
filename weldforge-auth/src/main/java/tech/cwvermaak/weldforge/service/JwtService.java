package tech.cwvermaak.weldforge.service;

import io.jsonwebtoken.*;
import io.micrometer.core.instrument.MeterRegistry;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import tech.cwvermaak.weldforge.config.security.HmacKeyRing;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@Service
@Slf4j
public class JwtService {

    public static final String CLAIM_TENANT_ID    = "tid";
    public static final String CLAIM_TENANT_SLUG  = "tenant";
    public static final String CLAIM_SUPER_ADMIN  = "sa";
    public static final String CLAIM_ADMIN_ROLE   = "adm";
    public static final String CLAIM_PURPOSE      = "purpose";
    public static final String CLAIM_TOKEN_VERSION = "ver";
    /** RFC 8176 authentication methods used on this login. */
    public static final String CLAIM_AMR          = "amr";
    /** The login session (refresh-token family) this token was minted from. */
    public static final String CLAIM_SESSION_ID   = "sid";
    /**
     * The upstream identity provider that produced this session, as the social
     * registration id {@code {tenantSlug}-{provider}}; absent for a login this
     * server performed itself.
     *
     * <p>Truthful and unconditional, unlike {@link #CLAIM_AMR} on a federated
     * session, which since V71 may be <em>asserted</em> by a tenant's
     * configuration rather than observed. A relying party that would rather not
     * take our word for an upstream's authentication strength can read this and
     * decide for itself.
     */
    public static final String CLAIM_IDP          = "idp";
    public static final String PURPOSE_MFA_CHALLENGE = "mfa_challenge";
    public static final String PURPOSE_ACCESS       = "access";
    public static final String PURPOSE_CONSENT_CSRF = "consent_csrf";

    private static final long MFA_CHALLENGE_TTL_MS = 5 * 60 * 1000L;
    /** Consent CSRF tokens outlive the 5-min code TTL slightly to tolerate a slow user. */
    private static final long CONSENT_CSRF_TTL_MS = 10 * 60 * 1000L;

    @Value("${app.jwt.secret}")
    private String secret;

    /**
     * Retired secrets still accepted for verification during a rotation overlap
     * (B-JWT-2), comma-separated, newest first. Normally empty.
     *
     * <p>Env: {@code APP_JWT_PREVIOUS_SECRETS}. Every entry is held to the same
     * 64-byte floor as the signing key by {@code SecretHygieneValidator}.
     */
    @Value("${app.jwt.previous-secrets:}")
    private String previousSecrets;

    /**
     * Optional on purpose: the unit tests construct this service directly, and
     * a counter is not worth making them all stand up a registry.
     */
    @org.springframework.beans.factory.annotation.Autowired(required = false)
    private MeterRegistry meterRegistry;

    /**
     * Built from the two fields above and rebuilt when they change.
     *
     * <p>Cached rather than rebuilt per call because deriving it costs a SHA-256
     * and a key construction per entry, and {@code parse} is on every
     * authenticated request. Keyed on the configured values rather than built
     * once, because the tests set {@code secret} by reflection after
     * construction and a once-only ring would silently keep the old key.
     */
    private volatile HmacKeyRing keyRing;

    /**
     * The key ring: one key signs, several may verify.
     *
     * <p>Kept in {@link HmacKeyRing} rather than inline so the guarantee that
     * matters — a retired key verifies and never signs — lives in one named,
     * documented place instead of being a property of this method.
     */
    private HmacKeyRing keyRing() {
        HmacKeyRing current = keyRing;
        if (current == null || !current.wasBuiltFrom(secret, previousSecrets)) {
            current = HmacKeyRing.of(secret, previousSecrets);
            keyRing = current;
        }
        return current;
    }

    /**
     * Platform audience stamped on access tokens and required by
     * {@link tech.cwvermaak.weldforge.config.JwtAuthenticationFilter} (B-JWT-1).
     * Scopes WeldForge's API to tokens explicitly minted for it — the shared
     * HMAC key is also used by external consumers, so an unscoped token of a
     * different intended audience must not authenticate here.
     */
    @Value("${app.jwt.audience:weldforge}")
    private String audience;

    @Value("${app.jwt.access-token-expiration-ms}")
    private long accessExpirationMs;

    @Value("${app.jwt.refresh-token-expiration-ms:604800000}")
    private long refreshExpirationMs;

    private SecretKey getSigningKey() {
        return keyRing().signingKey();
    }

    public String generateAccessToken(String email, Long tenantId, String tenantSlug,
                                      boolean superAdmin, int tokenVersion) {
        return generateAccessToken(email, tenantId, tenantSlug, superAdmin, tokenVersion, null, null);
    }

    /**
     * Full overload with an explicit issuer claim. Used by {@code AuthService}
     * to stamp the canonical per-tenant apex URL ({@code https://<base>/t/<slug>})
     * onto every access token so the OIDC discovery {@code issuer} value
     * matches what the JWT carries.
     */
    public String generateAccessToken(String email, Long tenantId, String tenantSlug,
                                      boolean superAdmin, int tokenVersion,
                                      Long tenantTtlMs, Map<String, Object> customClaims,
                                      String adminRole, String issuer) {
        return generateAccessTokenInternal(email, tenantId, tenantSlug, superAdmin,
                tokenVersion, tenantTtlMs, customClaims, adminRole, issuer, null, null, null);
    }

    /**
     * Full overload carrying the authentication methods (RFC 8176 {@code amr})
     * of the login this token represents. Only the login paths in
     * {@code AuthService} know which factors were actually exercised, so only
     * they can populate it — every other overload leaves the claim off rather
     * than guessing.
     */
    public String generateAccessToken(String email, Long tenantId, String tenantSlug,
                                      boolean superAdmin, int tokenVersion,
                                      Long tenantTtlMs, Map<String, Object> customClaims,
                                      String adminRole, String issuer, List<String> amr) {
        return generateAccessTokenInternal(email, tenantId, tenantSlug, superAdmin,
                tokenVersion, tenantTtlMs, customClaims, adminRole, issuer, amr, null, null);
    }

    /**
     * As above, also naming the browser session the token belongs to.
     *
     * @param sessionId the refresh-token family minted at login. Stable across
     *                  refreshes, so it identifies the session rather than the
     *                  token -- which is what SAML {@code SessionIndex} and
     *                  single-session logout need (CONF-5.2).
     */
    public String generateAccessToken(String email, Long tenantId, String tenantSlug,
                                      boolean superAdmin, int tokenVersion,
                                      Long tenantTtlMs, Map<String, Object> customClaims,
                                      String adminRole, String issuer, List<String> amr,
                                      String sessionId) {
        return generateAccessTokenInternal(email, tenantId, tenantSlug, superAdmin,
                tokenVersion, tenantTtlMs, customClaims, adminRole, issuer, amr, sessionId, null);
    }

    /**
     * As above, also naming the upstream provider that produced the session.
     *
     * @param idp the social registration id ({@code {tenantSlug}-{provider}}),
     *            or null when this server authenticated the person itself.
     *            Only the federated login path can know it, so every other
     *            overload leaves the claim off rather than guessing.
     */
    public String generateAccessToken(String email, Long tenantId, String tenantSlug,
                                      boolean superAdmin, int tokenVersion,
                                      Long tenantTtlMs, Map<String, Object> customClaims,
                                      String adminRole, String issuer, List<String> amr,
                                      String sessionId, String idp) {
        return generateAccessTokenInternal(email, tenantId, tenantSlug, superAdmin,
                tokenVersion, tenantTtlMs, customClaims, adminRole, issuer, amr, sessionId, idp);
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
        return generateAccessToken(email, tenantId, tenantSlug, superAdmin,
                tokenVersion, tenantTtlMs, customClaims,
                superAdmin ? "SUPER_ADMIN" : "NONE");
    }

    /**
     * Admin-role overload — used by older call sites that don't supply an
     * issuer. Prefer the overload that takes an explicit {@code issuer}
     * so the {@code iss} claim matches the OIDC discovery document.
     */
    public String generateAccessToken(String email, Long tenantId, String tenantSlug,
                                      boolean superAdmin, int tokenVersion,
                                      Long tenantTtlMs, Map<String, Object> customClaims,
                                      String adminRole) {
        return generateAccessTokenInternal(email, tenantId, tenantSlug, superAdmin,
                tokenVersion, tenantTtlMs, customClaims, adminRole, null, null, null, null);
    }

    private String generateAccessTokenInternal(String email, Long tenantId, String tenantSlug,
                                               boolean superAdmin, int tokenVersion,
                                               Long tenantTtlMs, Map<String, Object> customClaims,
                                               String adminRole, String issuer, List<String> amr,
                                               String sessionId, String idp) {
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
        claims.put(CLAIM_ADMIN_ROLE, adminRole == null ? "NONE" : adminRole);
        claims.put(CLAIM_PURPOSE, PURPOSE_ACCESS);
        claims.put(CLAIM_TOKEN_VERSION, tokenVersion);
        // Omitted rather than empty when unknown: a relying party reading an
        // absent amr knows nothing was asserted, whereas an empty array reads
        // as "authenticated by no method at all".
        if (amr != null && !amr.isEmpty()) {
            claims.put(CLAIM_AMR, List.copyOf(amr));
        }
        if (sessionId != null && !sessionId.isBlank()) {
            claims.put(CLAIM_SESSION_ID, sessionId);
        }
        // Absent for a login this server performed itself, so a relying party
        // reading no idp knows the authentication was ours rather than being
        // left to guess from an empty string.
        if (idp != null && !idp.isBlank()) {
            claims.put(CLAIM_IDP, idp);
        }

        long ttl = tenantTtlMs != null && tenantTtlMs > 0 ? tenantTtlMs : accessExpirationMs;
        JwtBuilder b = Jwts.builder()
                .subject(email)
                .claims(claims)
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + ttl));
        // Platform audience (B-JWT-1) — required by JwtAuthenticationFilter.
        if (audience != null && !audience.isBlank()) {
            b.audience().add(audience).and();
        }
        // OIDC: iss must match the discovery document. Setting it after the
        // claims map ensures the registered claim takes precedence over any
        // tenant-supplied custom claim of the same name.
        if (issuer != null && !issuer.isBlank()) {
            b.issuer(issuer);
        }
        // kid so a multi-key verifier can pick directly instead of trying
        // every key it holds. See HmacKeyRing.
        return b.header().keyId(keyRing().signingKeyId()).and()
                .signWith(getSigningKey()).compact();
    }

    private static boolean isReservedClaim(String name) {
        return switch (name) {
            case "sub", "iss", "aud", "exp", "iat", "nbf", "jti",
                 CLAIM_TENANT_ID, CLAIM_TENANT_SLUG, CLAIM_SUPER_ADMIN,
                 CLAIM_ADMIN_ROLE, CLAIM_PURPOSE, CLAIM_TOKEN_VERSION,
                 CLAIM_AMR, CLAIM_SESSION_ID, CLAIM_IDP -> true;
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
                .header().keyId(keyRing().signingKeyId()).and()
                .id(java.util.UUID.randomUUID().toString())   // jti — enables single-use (B-MFA-2)
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

    /**
     * Anti-CSRF token for the OIDC consent screen. Minted at /authorize render
     * time, bound to the authenticated user (sub = email) and tenant, and
     * embedded as a hidden field. The /authorize/decide endpoint requires a
     * valid one whose subject matches the session principal — an attacker
     * cross-site-submitting the consent form cannot mint or read such a token
     * (it requires the signing secret, and the Same-Origin Policy blocks
     * reading the rendered form), so consent CSRF is prevented even though the
     * decide endpoint is permitAll and global CSRF is disabled.
     */
    public String generateConsentCsrfToken(String email, Long tenantId, String tenantSlug) {
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put(CLAIM_TENANT_ID, tenantId);
        claims.put(CLAIM_TENANT_SLUG, tenantSlug == null ? "" : tenantSlug);
        claims.put(CLAIM_PURPOSE, PURPOSE_CONSENT_CSRF);
        return Jwts.builder()
                .header().keyId(keyRing().signingKeyId()).and()
                .subject(email)
                .claims(claims)
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + CONSENT_CSRF_TTL_MS))
                .signWith(getSigningKey())
                .compact();
    }

    public boolean isConsentCsrf(io.jsonwebtoken.Claims claims) {
        Object p = claims.get(CLAIM_PURPOSE);
        return PURPOSE_CONSENT_CSRF.equals(p == null ? null : p.toString());
    }

    /**
     * Verify against the key ring (B-JWT-2).
     *
     * <p>The signing key is tried first, so the overwhelmingly common case — a
     * token this server minted minutes ago — costs exactly what it did before
     * the ring existed. A retired key is reached only by a token that genuinely
     * needs one, which is the whole point of the overlap window.
     *
     * <p>When a retired key is what verifies, that is recorded: the counter is
     * the only way an operator can answer "has everything moved off the old
     * secret yet?" before deciding to drop it. Without it the decision is a
     * guess, and guessing early logs everyone out — which is the failure this
     * change exists to prevent.
     *
     * <p><b>Only a signature mismatch advances to the next key.</b> Everything
     * else — expired, malformed, unsupported — propagates as the real JJWT
     * exception. That distinction matters more than it looks: JJWT reports
     * expiry only <em>after</em> the signature has verified, so an
     * {@code ExpiredJwtException} already tells us the right key was found and
     * trying the rest is pointless. An earlier draft of this method swallowed
     * every exception while walking the ring, which turned every ordinary
     * expiry — far and away the most common legitimate failure — into
     * "signature does not match", hiding the cause from the logs and from
     * callers that distinguish the two.
     */
    public Claims parse(String token) {
        // kid is a hint, not a requirement: a token minted by a build from
        // before this change carries none, and must keep working.
        String kid = peekKeyId(token);
        if (kid != null) {
            SecretKey hinted = keyRing().keyById(kid).orElse(null);
            if (hinted != null) {
                // Authoritative: the token names a key we hold, so its failure
                // is the answer. No fallback -- a kid we recognise whose
                // signature does not check out is a forgery, not a reason to go
                // looking for a key that would accept it.
                Claims claims = verifyWith(token, hinted);
                recordKeyUse(kid);
                return claims;
            }
            // An unknown kid falls through to the ring rather than being
            // refused outright: a consumer may label tokens with a scheme of
            // its own, and the signature is what decides either way.
        }

        List<Map.Entry<String, SecretKey>> keys = keyRing().verificationKeys();
        for (int i = 0; i < keys.size(); i++) {
            boolean last = i == keys.size() - 1;
            try {
                Claims claims = verifyWith(token, keys.get(i).getValue());
                recordKeyUse(keys.get(i).getKey());
                return claims;
            } catch (io.jsonwebtoken.security.SignatureException e) {
                // Wrong key for this token. Try the next, unless that was the
                // last -- then this is the genuine answer.
                if (last) {
                    throw e;
                }
            }
        }
        // Unreachable: the ring always holds at least the signing key, so the
        // loop either returns or throws.
        throw new JwtException("No verification key available");
    }

    private Claims verifyWith(String token, SecretKey key) {
        return Jwts.parser()
                .verifyWith(key)
                .clockSkewSeconds(60)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    /**
     * The {@code kid} from the header without verifying anything.
     *
     * <p>Unverified input, so it is used only to look up a key we already hold
     * — never trusted for a decision. An attacker-chosen kid at worst selects a
     * key whose signature then fails.
     */
    private String peekKeyId(String token) {
        try {
            int firstDot = token.indexOf('.');
            if (firstDot <= 0) return null;
            String json = new String(java.util.Base64.getUrlDecoder()
                    .decode(token.substring(0, firstDot)), java.nio.charset.StandardCharsets.UTF_8);
            // Deliberately not a JSON parse: this runs on every request with
            // unverified bytes, and the value wanted is one short string.
            int at = json.indexOf("\"kid\"");
            if (at < 0) return null;
            int colon = json.indexOf(':', at);
            int open = json.indexOf('"', colon + 1);
            int close = json.indexOf('"', open + 1);
            if (colon < 0 || open < 0 || close < 0) return null;
            return json.substring(open + 1, close);
        } catch (RuntimeException e) {
            return null;
        }
    }

    private void recordKeyUse(String kid) {
        if (meterRegistry == null || !keyRing().rotationInProgress()) {
            return;
        }
        boolean retired = !kid.equals(keyRing().signingKeyId());
        meterRegistry.counter("weldforge.jwt.verified",
                "kid", kid,
                "key", retired ? "retired" : "signing").increment();
        if (retired) {
            // Debug, not warn: during an overlap this is expected and routine,
            // and at access-token volume a warn per request would bury the log.
            // The counter is the signal; this is for when someone is looking.
            log.debug("Token verified under retired key kid={} -- overlap window still in use", kid);
        }
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

    /** The platform audience expected on access tokens. */
    public String getAudience() { return audience; }

    /**
     * True when the token carries the configured platform audience (B-JWT-1).
     * If no audience is configured (e.g. a bare unit-test instance), the check
     * is a no-op pass so callers stay backward-compatible.
     */
    public boolean hasValidAudience(Claims claims) {
        if (audience == null || audience.isBlank()) return true;
        java.util.Set<String> auds = claims.getAudience();
        return auds != null && auds.contains(audience);
    }

    public long getExpirationTime() { return accessExpirationMs / 1000; }
    public long getRefreshTokenExpirationTime() { return refreshExpirationMs / 1000; }
}
