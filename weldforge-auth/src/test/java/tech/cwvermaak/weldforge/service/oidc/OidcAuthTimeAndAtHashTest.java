package tech.cwvermaak.weldforge.service.oidc;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;
import tech.cwvermaak.weldforge.model.OidcClient;
import tech.cwvermaak.weldforge.model.Tenant;
import tech.cwvermaak.weldforge.model.TenantSigningKey;
import tech.cwvermaak.weldforge.model.User;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * CONF-2.2 ({@code auth_time}) and CONF-2.4 ({@code at_hash}).
 *
 * <p>{@code auth_time} answers a question no other claim does: {@code iat} says
 * when the <em>token</em> was minted, which a refresh moves forward
 * indefinitely, while {@code auth_time} says when the <em>person</em> last
 * proved who they are. A relying party protecting a sensitive operation gates
 * on the second and would be misled by the first.
 */
class OidcAuthTimeAndAtHashTest {

    private OidcTokenService tokenService;
    private Tenant leap;
    private OidcClient client;
    private User alice;
    private RSAPublicKey publicKey;

    @BeforeEach
    void setUp() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(2048);
        KeyPair pair = gen.generateKeyPair();
        publicKey = (RSAPublicKey) pair.getPublic();

        leap = Tenant.builder().id(1L).slug("leap").name("Leap").build();
        client = OidcClient.builder().id(10L).tenant(leap).clientId("portal").build();
        alice = User.builder().id(42L).tenant(leap).email("alice@leap.test").build();

        TenantSigningKey keyRow = new TenantSigningKey();
        keyRow.setKid("kid-1");
        keyRow.setTenant(leap);

        TenantSigningKeyService signingKeyService = mock(TenantSigningKeyService.class);
        when(signingKeyService.getOrCreateActive(any())).thenReturn(keyRow);
        when(signingKeyService.loadPrivateKey(keyRow)).thenReturn((RSAPrivateKey) pair.getPrivate());
        when(signingKeyService.loadPublicKey(keyRow)).thenReturn(publicKey);

        tokenService = new OidcTokenService(signingKeyService, new SimpleMeterRegistry());
        ReflectionTestUtils.setField(tokenService, "accessTokenSeconds", 3600L);
        ReflectionTestUtils.setField(tokenService, "idTokenSeconds", 3600L);
    }

    private Claims idClaims(OidcTokenService.IssuedTokens tokens) {
        return Jwts.parser().verifyWith(publicKey).build()
                .parseSignedClaims(tokens.idToken()).getPayload();
    }

    private OidcTokenService.IssuedTokens issue(Instant authTime) {
        return tokenService.issueForCodeExchange(leap, client, alice,
                List.of("openid", "email"), "nonce-1",
                "https://sso.weldforge.org/t/leap", List.of("pwd"), authTime);
    }

    @Test
    @DisplayName("auth_time reports the login, in epoch seconds")
    void auth_time_is_emitted() {
        Instant loggedInAt = Instant.now().minusSeconds(600);

        Claims claims = idClaims(issue(loggedInAt));

        assertThat(claims.get("auth_time", Number.class).longValue())
                .isEqualTo(loggedInAt.getEpochSecond());
    }

    @Test
    @DisplayName("auth_time is older than iat when the login predates the token")
    void auth_time_precedes_iat() {
        Claims claims = idClaims(issue(Instant.now().minusSeconds(600)));

        // This is the whole point of the claim: iat moves forward on every
        // refresh, auth_time does not.
        assertThat(claims.get("auth_time", Number.class).longValue())
                .isLessThan(claims.getIssuedAt().toInstant().getEpochSecond());
    }

    @Test
    @DisplayName("An unknown login time omits the claim rather than inventing one")
    void auth_time_omitted_when_unknown() {
        // Grants predating V53 have no recorded time. A relying party acts on
        // auth_time as evidence, so defaulting it to "now" would assert a fresh
        // authentication that never happened.
        assertThat(idClaims(issue(null)).get("auth_time")).isNull();
    }

    @Test
    @DisplayName("at_hash is the base64url left half of the access token's SHA-256")
    void at_hash_matches_the_access_token() throws Exception {
        var tokens = issue(Instant.now());

        byte[] digest = MessageDigest.getInstance("SHA-256")
                .digest(tokens.accessToken().getBytes(StandardCharsets.US_ASCII));
        String expected = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(Arrays.copyOf(digest, digest.length / 2));

        assertThat(idClaims(tokens).get("at_hash")).isEqualTo(expected);
    }

    @Test
    @DisplayName("at_hash binds THIS access token, so a substituted one is detectable")
    void at_hash_differs_per_access_token() {
        // The grants must genuinely differ: two tokens minted in the same
        // second with identical claims are byte-identical, so an at_hash that
        // matched would prove nothing about binding.
        var forEmail = tokenService.issueForCodeExchange(leap, client, alice,
                List.of("openid", "email"), "nonce-1",
                "https://sso.weldforge.org/t/leap", List.of("pwd"), Instant.now());
        var forProfile = tokenService.issueForCodeExchange(leap, client, alice,
                List.of("openid", "profile"), "nonce-2",
                "https://sso.weldforge.org/t/leap", List.of("pwd"), Instant.now());

        assertThat(forEmail.accessToken()).isNotEqualTo(forProfile.accessToken());
        assertThat(idClaims(forEmail).get("at_hash"))
                .isNotEqualTo(idClaims(forProfile).get("at_hash"));
    }

    @Test
    @DisplayName("A tenant custom claim cannot forge auth_time or at_hash")
    void tenant_claims_cannot_forge() {
        // Both are things a relying party acts on. Letting tenant config assert
        // them would make the assertion worthless -- the same reasoning already
        // applied to amr.
        leap.setCustomClaims(java.util.Map.of(
                "auth_time", 1, "at_hash", "forged", "amr", List.of("hwk")));

        Claims claims = idClaims(issue(Instant.now().minusSeconds(60)));

        assertThat(claims.get("auth_time", Number.class).longValue()).isNotEqualTo(1L);
        assertThat(claims.get("at_hash")).isNotEqualTo("forged");
        assertThat(claims.get("amr")).isEqualTo(List.of("pwd"));
    }
}
