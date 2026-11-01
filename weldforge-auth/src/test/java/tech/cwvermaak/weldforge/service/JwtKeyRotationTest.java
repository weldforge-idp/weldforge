package tech.cwvermaak.weldforge.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;
import tech.cwvermaak.weldforge.config.security.HmacKeyRing;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Date;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Rotating the platform HMAC without an outage (B-JWT-2 / CONF-7.4).
 *
 * <p>With a single key this was a hard cutover. {@code app.jwt.secret} is shared
 * verbatim with three external consumers, so the instant it changed, every token
 * signed under the old one failed verification in WeldForge <em>and</em> in all
 * three consumers simultaneously. The runbook said in as many words: you cannot
 * stage it. Each test below is one half of making it stageable.
 */
@DisplayName("Platform HMAC rotation")
class JwtKeyRotationTest {

    private static final String OLD_SECRET =
            "the-previous-platform-secret-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    private static final String NEW_SECRET =
            "the-rotated-platform-secret-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    private static final String FOREIGN_SECRET =
            "a-key-that-is-in-no-ring-anywhere-dddddddddddddddddddddddddddddddddd";

    /** A service configured as one deployment: active key, plus any retired keys. */
    private static JwtService serviceWith(String active, String previous) {
        JwtService s = new JwtService();
        ReflectionTestUtils.setField(s, "secret", active);
        ReflectionTestUtils.setField(s, "previousSecrets", previous);
        ReflectionTestUtils.setField(s, "accessExpirationMs", 60_000L);
        ReflectionTestUtils.setField(s, "refreshExpirationMs", 600_000L);
        ReflectionTestUtils.setField(s, "audience", "weldforge");
        return s;
    }

    private static String headerOf(String token) {
        return new String(Base64.getUrlDecoder()
                .decode(token.substring(0, token.indexOf((int) '.'))), StandardCharsets.UTF_8);
    }

    @Test
    @DisplayName("THE POINT: a token signed under the old secret still verifies after rotation")
    void tokenFromBeforeRotationStillVerifies() {
        JwtService before = serviceWith(OLD_SECRET, "");
        String issuedBeforeRotation =
                before.generateAccessToken("alice@acme.test", 42L, "acme", false);

        // The new secret is now active; the old one is retained for the overlap.
        // The token minted a moment ago must keep working, which is the whole
        // reason the ring exists.
        JwtService after = serviceWith(NEW_SECRET, OLD_SECRET);

        Claims claims = after.parse(issuedBeforeRotation);
        assertThat(claims.getSubject()).isEqualTo("alice@acme.test");
    }

    @Test
    @DisplayName("once the overlap is closed, the old token is refused")
    void afterOverlapClosesOldTokenIsRefused() {
        String old = serviceWith(OLD_SECRET, "")
                .generateAccessToken("alice@acme.test", 42L, "acme", false);

        JwtService closed = serviceWith(NEW_SECRET, "");

        assertThat(closed.isTokenValid(old)).isFalse();
        assertThatThrownBy(() -> closed.parse(old)).isInstanceOf(RuntimeException.class);
    }

    @Test
    @DisplayName("THE SAFETY PROPERTY: a retired key never signs")
    void retiredKeyNeverSigns() {
        JwtService during = serviceWith(NEW_SECRET, OLD_SECRET);
        String fresh = during.generateAccessToken("alice@acme.test", 42L, "acme", false);

        // Minted under the ACTIVE key, so a consumer that has already dropped
        // the old secret accepts it. If a retired key could sign, a rotation
        // would mint tokens the moved-on consumers already reject -- the exact
        // outage this change removes, reintroduced from the other direction.
        assertThat(serviceWith(NEW_SECRET, "").isTokenValid(fresh)).isTrue();
        assertThat(serviceWith(OLD_SECRET, "").isTokenValid(fresh)).isFalse();
    }

    @Test
    @DisplayName("tokens carry a kid, derived from the key so a consumer can compute it")
    void tokensCarryKid() {
        String token = serviceWith(NEW_SECRET, "")
                .generateAccessToken("alice@acme.test", 42L, "acme", false);

        assertThat(headerOf(token)).contains(HmacKeyRing.keyId(NEW_SECRET));
    }

    @Test
    @DisplayName("the mfa-challenge and consent-csrf tokens rotate too")
    void otherTokenKindsAlsoRotate() {
        JwtService before = serviceWith(OLD_SECRET, "");
        String challenge = before.generateMfaChallengeToken(7L, 42L, "acme");
        String csrf = before.generateConsentCsrfToken("alice@acme.test", 42L, "acme");

        JwtService after = serviceWith(NEW_SECRET, OLD_SECRET);

        // A user mid-MFA when the secret rotates must not be stranded, and an
        // already-rendered consent form must not start failing CSRF.
        assertThat(after.isMfaChallenge(after.parse(challenge))).isTrue();
        assertThat(after.isConsentCsrf(after.parse(csrf))).isTrue();
    }

    @Test
    @DisplayName("a token with no kid still verifies — it was minted before this change")
    void tokenWithoutKidStillVerifies() {
        // The shape every token in flight had at the moment this deployed.
        // Treating kid as a hint rather than a requirement is what stops the
        // upgrade itself from being the outage.
        String noKid = Jwts.builder()
                .subject("alice@acme.test")
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + 60_000))
                .signWith(Keys.hmacShaKeyFor(NEW_SECRET.getBytes(StandardCharsets.UTF_8)))
                .compact();

        assertThat(headerOf(noKid)).doesNotContain("kid");
        assertThat(serviceWith(NEW_SECRET, OLD_SECRET).parse(noKid).getSubject())
                .isEqualTo("alice@acme.test");
    }

    @Test
    @DisplayName("a forgery labelled with a known kid is refused, not retried into acceptance")
    void forgedTokenWithKnownKidIsRefused() {
        // kid is unverified input. It may select a key; it may never excuse a
        // signature. A naive implementation that trusted the label, or that
        // kept trying other keys until one worked, would differ here.
        String forged = Jwts.builder()
                .header().keyId(HmacKeyRing.keyId(NEW_SECRET)).and()
                .subject("attacker@evil.test")
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + 60_000))
                .signWith(Keys.hmacShaKeyFor(FOREIGN_SECRET.getBytes(StandardCharsets.UTF_8)))
                .compact();

        assertThat(serviceWith(NEW_SECRET, OLD_SECRET).isTokenValid(forged)).isFalse();
    }

    @Test
    @DisplayName("a forgery labelled with an unknown kid is refused")
    void forgedTokenWithUnknownKidIsRefused() {
        String forged = Jwts.builder()
                .header().keyId("0000000000000000").and()
                .subject("attacker@evil.test")
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + 60_000))
                .signWith(Keys.hmacShaKeyFor(FOREIGN_SECRET.getBytes(StandardCharsets.UTF_8)))
                .compact();

        assertThat(serviceWith(NEW_SECRET, OLD_SECRET).isTokenValid(forged)).isFalse();
    }

    @Test
    @DisplayName("a token signed by a key the ring does not hold is refused")
    void unknownKeyIsRefused() {
        String foreign = Jwts.builder()
                .subject("attacker@evil.test")
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + 60_000))
                .signWith(Keys.hmacShaKeyFor(FOREIGN_SECRET.getBytes(StandardCharsets.UTF_8)))
                .compact();

        assertThat(serviceWith(NEW_SECRET, OLD_SECRET).isTokenValid(foreign)).isFalse();
    }

    @Test
    @DisplayName("an expired token still reports expiry, not a signature failure")
    void expiryIsStillTheRealError() {
        // parse() swallows failures while walking the ring. If the final throw
        // were synthetic, every expiry would surface as a bad signature and the
        // real cause would vanish from the logs.
        // Past the parser's deliberate 60-second clock skew allowance, or it
        // would still be accepted and this would assert nothing.
        JwtService s = serviceWith(NEW_SECRET, OLD_SECRET);
        ReflectionTestUtils.setField(s, "accessExpirationMs", -120_000L);
        String expired = s.generateAccessToken("alice@acme.test", 42L, "acme", false);

        assertThatThrownBy(() -> s.parse(expired)).isInstanceOf(ExpiredJwtException.class);
    }

    @Test
    @DisplayName("an expired token signed under a RETIRED key still reports expiry")
    void expiredUnderRetiredKeyStillReportsExpiry() {
        // The sharp version of the test above, and the one that caught a real
        // bug here: walking the ring must not swallow expiry. JJWT reports
        // expiry only after the signature has verified, so reaching
        // ExpiredJwtException already proves the right key was found — treating
        // it as "wrong key, try the next" turned every ordinary expiry during a
        // rotation into a misleading signature error.
        JwtService old = serviceWith(OLD_SECRET, "");
        ReflectionTestUtils.setField(old, "accessExpirationMs", -120_000L);
        String expiredOldToken = old.generateAccessToken("alice@acme.test", 42L, "acme", false);

        JwtService during = serviceWith(NEW_SECRET, OLD_SECRET);

        assertThatThrownBy(() -> during.parse(expiredOldToken))
                .isInstanceOf(ExpiredJwtException.class);
    }

    @Test
    @DisplayName("an unknown kid falls through to the ring and the signature decides")
    void unknownKidFallsThroughToTheRing() {
        // A consumer may label its tokens with a kid scheme of its own. Refusing
        // on an unrecognised label would break it for no security gain, since
        // the signature is what actually decides.
        String labelledOddly = Jwts.builder()
                .header().keyId("someone-elses-scheme").and()
                .subject("alice@acme.test")
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + 60_000))
                .signWith(Keys.hmacShaKeyFor(OLD_SECRET.getBytes(StandardCharsets.UTF_8)))
                .compact();

        assertThat(serviceWith(NEW_SECRET, OLD_SECRET).parse(labelledOddly).getSubject())
                .isEqualTo("alice@acme.test");
    }

    @Test
    @DisplayName("no rotation configured behaves exactly as before — the default-off guard")
    void noRotationIsUnchanged() {
        JwtService s = serviceWith(NEW_SECRET, "");
        String token = s.generateAccessToken("alice@acme.test", 42L, "acme", false);

        assertThat(s.parse(token).getSubject()).isEqualTo("alice@acme.test");
        assertThat(serviceWith(NEW_SECRET, null).isTokenValid(token)).isTrue();
    }
}
