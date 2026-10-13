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

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * What a per-client access TTL actually does to an issued token.
 *
 * <p>{@link AccessTokenLifetimeTest} covers the resolution rule in isolation;
 * this covers the thing that matters to a relying party, which is that the
 * {@code exp} in the token and the {@code expires_in} in the response agree
 * with each other and with the client's registration (B-OIDC-5).
 */
@DisplayName("OidcTokenService — per-client access-token lifetime")
class OidcAccessTokenTtlTest {

    private static final String ISSUER = "https://sso.weldforge.org/t/acme";
    /** One hour, to make "the client asked for less" unambiguous. */
    private static final long TENANT_TTL_MS = 3_600_000L;

    private OidcTokenService service;
    private TenantSigningKeyService signingKeyService;
    private PublicKey publicKey;

    private Tenant tenant;
    private User user;

    @BeforeEach
    void setUp() throws Exception {
        KeyPair kp = KeyPairGenerator.getInstance("RSA").genKeyPair();
        publicKey = kp.getPublic();

        signingKeyService = mock(TenantSigningKeyService.class);
        TenantSigningKey signingKey = mock(TenantSigningKey.class);
        when(signingKey.getKid()).thenReturn("test-kid");
        when(signingKeyService.getOrCreateActive(any())).thenReturn(signingKey);
        when(signingKeyService.loadPrivateKey(any())).thenReturn((RSAPrivateKey) kp.getPrivate());

        // Unstubbed, so no roles. This suite asserts on lifetimes, not claims.
        var roleRepository = mock(tech.cwvermaak.weldforge.repository.RoleRepository.class);
        service = new OidcTokenService(signingKeyService, new SimpleMeterRegistry(), roleRepository,
                new AccessTokenLifetime(3600L));
        ReflectionTestUtils.setField(service, "idTokenSeconds", 3600L);

        tenant = Tenant.builder().id(1L).slug("acme").name("Acme")
                .accessTtlMs(TENANT_TTL_MS).build();
        user = User.builder().id(7L).tenant(tenant).email("alice@acme.test").build();
    }

    private OidcClient client(Integer accessTokenTtlSeconds) {
        return OidcClient.builder().id(10L).tenant(tenant).clientId("acme-app")
                .scopes("openid").grantTypes("authorization_code")
                .accessTokenTtlSeconds(accessTokenTtlSeconds)
                .build();
    }

    private Claims claims(String token) {
        return Jwts.parser().verifyWith(publicKey).build().parseSignedClaims(token).getPayload();
    }

    /** Seconds between iat and exp, which is the lifetime the token really has. */
    private long lifetimeOf(String token) {
        Claims c = claims(token);
        return (c.getExpiration().getTime() - c.getIssuedAt().getTime()) / 1000;
    }

    @Test
    @DisplayName("a client that registered a shorter lifetime gets it, and expires_in says so")
    void clientShorterThanTenant() {
        var out = service.issueForCodeExchange(
                tenant, client(300), user, List.of("openid"), null, ISSUER);

        assertThat(out.expiresIn()).isEqualTo(300L);
        assertThat(lifetimeOf(out.accessToken())).isEqualTo(300L);
    }

    @Test
    @DisplayName("a client with no lifetime of its own still gets the tenant's")
    void clientInheritsTenant() {
        var out = service.issueForCodeExchange(
                tenant, client(null), user, List.of("openid"), null, ISSUER);

        assertThat(out.expiresIn()).isEqualTo(TENANT_TTL_MS / 1000);
        assertThat(lifetimeOf(out.accessToken())).isEqualTo(TENANT_TTL_MS / 1000);
    }

    /**
     * Registration refuses a value above the tenant's, so the only way to
     * reach this is for the tenant to have lowered its own TTL afterwards.
     * Nothing re-validates stored clients when that happens, so the cap has
     * to hold here too or the old value would outlive the policy.
     */
    @Test
    @DisplayName("a stored lifetime above the tenant's is capped when the token is minted")
    void storedValueAboveTheCeilingIsCapped() {
        Tenant lowered = Tenant.builder().id(1L).slug("acme").name("Acme")
                .accessTtlMs(600_000L).build();

        var out = service.issueForCodeExchange(
                lowered, client(86_400), user, List.of("openid"), null, ISSUER);

        assertThat(out.expiresIn()).isEqualTo(600L);
        assertThat(lifetimeOf(out.accessToken())).isEqualTo(600L);
    }

    /**
     * The column is access_token_ttl_s. An ID token is spent once at sign-in
     * to establish a session, and shortening it as a side effect would be a
     * second, undocumented behaviour riding on one field.
     */
    @Test
    @DisplayName("the ID token keeps the tenant's lifetime, not the client's shorter one")
    void idTokenIsUnaffected() {
        var out = service.issueForCodeExchange(
                tenant, client(300), user, List.of("openid"), null, ISSUER);

        assertThat(lifetimeOf(out.accessToken())).isEqualTo(300L);
        assertThat(lifetimeOf(out.idToken())).isEqualTo(TENANT_TTL_MS / 1000);
    }

    @Test
    @DisplayName("client_credentials honours the client's lifetime too")
    void clientCredentials() {
        var out = service.issueForClientCredentials(
                tenant, client(300), List.of("openid"), ISSUER);

        assertThat(out.expiresIn()).isEqualTo(300L);
        assertThat(lifetimeOf(out.accessToken())).isEqualTo(300L);
        assertThat(out.idToken()).isNull();
    }
}
