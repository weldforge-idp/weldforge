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

        // V62: the roles claim is read from the repository, not from a lazy
        // collection. These suites assert other claims, so an empty set is fine.
        var roleRepositoryForTest = org.mockito.Mockito.mock(
                tech.cwvermaak.weldforge.repository.RoleRepository.class);
        tokenService = new OidcTokenService(signingKeyService, new SimpleMeterRegistry(), roleRepositoryForTest);
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

    /**
     * RFC 8707: where the audience actually lands.
     *
     * <p>Everything else about resource indicators is plumbing; this is the
     * payoff, and it is also the part that is easy to get subtly wrong. The
     * two {@code claims.put("aud", ...)} lines in the token service look
     * identical, and the first attempt at this change edited the ID token's.
     */
    @org.junit.jupiter.api.Nested
    @DisplayName("resource indicators decide the access token's audience")
    class ResourceAudience {

        private static final String MCP = "https://shot.cwvermaak.tech/mcp/counteract-studios";

        private Claims accessClaims(OidcTokenService.IssuedTokens tokens) {
            return Jwts.parser().verifyWith(publicKey).build()
                    .parseSignedClaims(tokens.accessToken()).getPayload();
        }

        private OidcTokenService.IssuedTokens issueFor(String resource) {
            return tokenService.issueForCodeExchange(leap, client, alice,
                    List.of("openid", "email"), "nonce-1",
                    "https://sso.weldforge.org/t/leap", List.of("pwd"), null, resource);
        }

        @Test
        @DisplayName("with no resource the audience is the client id, exactly as before")
        void no_resource_keeps_the_client_as_audience() {
            Claims access = accessClaims(issueFor(null));

            // The whole opt-in guarantee in one assertion. Live integrations
            // validate aud against their client id; if this ever changes for a
            // client that asked for nothing, they all break at once.
            assertThat(access.getAudience()).containsExactly(client.getClientId());
        }

        @Test
        @DisplayName("with a resource the access token is audienced to the resource")
        void resource_becomes_the_access_token_audience() {
            Claims access = accessClaims(issueFor(MCP));

            assertThat(access.getAudience()).containsExactly(MCP);
        }

        @Test
        @DisplayName("the ID token keeps the client as its audience, resource or not")
        void id_token_audience_is_always_the_client() {
            // OIDC Core defines the ID token as a token FOR the client, and a
            // conformant client validates aud against its own client id. An
            // ID token audienced to a resource server would fail that check
            // everywhere, which is why this is asserted separately rather than
            // assumed from the access-token test above.
            assertThat(idClaims(issueFor(MCP)).getAudience())
                    .containsExactly(client.getClientId());
            assertThat(idClaims(issueFor(null)).getAudience())
                    .containsExactly(client.getClientId());
        }

        @Test
        @DisplayName("client_id stays on the access token so the client is still identifiable")
        void client_id_claim_survives_a_resource_audience() {
            // aud now names the resource, so the only thing left saying which
            // client holds this token is the client_id claim. A resource
            // server that logs or authorises on the calling client needs it.
            assertThat(accessClaims(issueFor(MCP)).get("client_id", String.class))
                    .isEqualTo(client.getClientId());
        }
    }
}
