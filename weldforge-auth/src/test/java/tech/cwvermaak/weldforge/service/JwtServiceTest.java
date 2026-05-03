package tech.cwvermaak.weldforge.service;

import io.jsonwebtoken.Claims;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Guards the JWT claim contract. Critical because the filter chain relies
 * on the {@code purpose} claim to prevent mfa-challenge tokens from
 * authenticating arbitrary API calls.
 */
class JwtServiceTest {

    private JwtService jwt;

    @BeforeEach
    void setUp() {
        jwt = new JwtService();
        ReflectionTestUtils.setField(jwt, "secret",
                "test-secret-that-is-long-enough-for-hs256-signing-0123456789abcdef");
        ReflectionTestUtils.setField(jwt, "accessExpirationMs", 60_000L);
        ReflectionTestUtils.setField(jwt, "refreshExpirationMs", 600_000L);
    }

    @Test
    @DisplayName("access tokens carry sub, tid, tenant slug, sa, and purpose=access")
    void accessToken_carriesExpectedClaims() {
        String token = jwt.generateAccessToken("alice@acme.test", 42L, "acme", true);
        Claims claims = jwt.parse(token);

        assertThat(claims.getSubject()).isEqualTo("alice@acme.test");
        assertThat(((Number) claims.get(JwtService.CLAIM_TENANT_ID)).longValue()).isEqualTo(42L);
        assertThat(claims.get(JwtService.CLAIM_TENANT_SLUG)).isEqualTo("acme");
        assertThat(claims.get(JwtService.CLAIM_SUPER_ADMIN)).isEqualTo(true);
        assertThat(claims.get(JwtService.CLAIM_PURPOSE)).isEqualTo(JwtService.PURPOSE_ACCESS);
    }

    @Test
    @DisplayName("mfa challenge token carries purpose=mfa_challenge and the user id as sub")
    void mfaChallengeToken_isMarkedAsChallenge() {
        String token = jwt.generateMfaChallengeToken(42L, 7L, "acme");
        Claims claims = jwt.parse(token);

        assertThat(claims.getSubject()).isEqualTo("42");
        assertThat(claims.get(JwtService.CLAIM_PURPOSE)).isEqualTo(JwtService.PURPOSE_MFA_CHALLENGE);
        assertThat(jwt.isMfaChallenge(claims)).isTrue();
    }

    @Test
    @DisplayName("access token is not mistaken for an mfa_challenge token")
    void accessToken_isNotAChallenge() {
        Claims claims = jwt.parse(jwt.generateAccessToken("alice@acme.test", 1L, "acme", false));
        assertThat(jwt.isMfaChallenge(claims)).isFalse();
    }

    @Test
    @DisplayName("tamper-detected signatures fail validation")
    void tamperedToken_failsValidation() {
        String token = jwt.generateAccessToken("alice@acme.test", 1L, "acme", false);
        // Flip a character inside the signature segment.
        String tampered = token.substring(0, token.length() - 2)
                + (token.endsWith("A") ? "B" : "A");

        assertThat(jwt.isTokenValid(tampered)).isFalse();
    }

    @Test
    @DisplayName("garbage input is rejected cleanly, no stack trace leakage")
    void garbageToken_rejected() {
        assertThat(jwt.isTokenValid("not-a-jwt")).isFalse();
        assertThatThrownBy(() -> jwt.parse("not-a-jwt"))
                .isInstanceOf(Exception.class);
    }
}
