package tech.cwvermaak.weldforge.controller;

import io.jsonwebtoken.Jwts;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.web.MockHttpServletRequest;
import tech.cwvermaak.weldforge.model.Tenant;
import tech.cwvermaak.weldforge.model.TenantSigningKey;
import tech.cwvermaak.weldforge.model.User;
import tech.cwvermaak.weldforge.repository.RevokedOidcTokenRepository;
import tech.cwvermaak.weldforge.repository.TenantRepository;
import tech.cwvermaak.weldforge.repository.UserRepository;
import tech.cwvermaak.weldforge.service.oidc.TenantSigningKeyService;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * CONF-6.1 and CONF-6.2 — userinfo returns only what was granted, refuses
 * revoked tokens, and challenges properly on 401.
 *
 * <p>Real RS256 tokens are minted here rather than mocked claims: the endpoint's
 * job is to decide what a *verified* token entitles the caller to, and a mocked
 * parse would skip the part that has to hold.
 */
class OidcUserinfoScopeTest {

    private OidcUserinfoController controller;
    private RevokedOidcTokenRepository revocationRepository;
    private RSAPrivateKey privateKey;
    private Tenant leap;

    @BeforeEach
    void setUp() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(2048);
        KeyPair pair = gen.generateKeyPair();
        privateKey = (RSAPrivateKey) pair.getPrivate();
        RSAPublicKey publicKey = (RSAPublicKey) pair.getPublic();

        leap = new Tenant();
        leap.setId(1L);
        leap.setSlug("leap");

        User alice = new User();
        alice.setId(42L);
        alice.setEmail("alice@leap.test");
        alice.setName("Alice Example");
        alice.setImageUrl("https://cdn.example/alice.png");
        alice.setTenant(leap);

        TenantRepository tenantRepository = mock(TenantRepository.class);
        when(tenantRepository.findBySlug("leap")).thenReturn(Optional.of(leap));

        UserRepository userRepository = mock(UserRepository.class);
        when(userRepository.findById(42L)).thenReturn(Optional.of(alice));

        TenantSigningKey keyRow = new TenantSigningKey();
        keyRow.setKid("kid-1");
        keyRow.setTenant(leap);

        TenantSigningKeyService signingKeyService = mock(TenantSigningKeyService.class);
        when(signingKeyService.requireByKid("kid-1")).thenReturn(keyRow);
        when(signingKeyService.loadPublicKey(keyRow)).thenReturn(publicKey);

        revocationRepository = mock(RevokedOidcTokenRepository.class);
        when(revocationRepository.existsByTokenHash(anyString())).thenReturn(false);

        controller = new OidcUserinfoController(
                tenantRepository, userRepository, signingKeyService, revocationRepository);
    }

    private String token(String scope, String tokenType) {
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("iss", "https://sso.weldforge.org/t/leap");
        claims.put("sub", "42");
        claims.put("token_type", tokenType);
        if (scope != null) claims.put("scope", scope);
        return Jwts.builder()
                .header().keyId("kid-1").and()
                .claims(claims)
                .issuedAt(Date.from(Instant.now()))
                .expiration(Date.from(Instant.now().plusSeconds(300)))
                .signWith(privateKey, Jwts.SIG.RS256)
                .compact();
    }

    @SuppressWarnings("unchecked")
    private ResponseEntity<Map<String, Object>> call(String bearer) {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/t/leap/oauth2/userinfo");
        if (bearer != null) request.addHeader("Authorization", "Bearer " + bearer);
        return controller.userinfo("leap", request);
    }

    @Test
    @DisplayName("openid alone returns the subject and nothing else")
    void openid_only_returns_sub() {
        var response = call(token("openid", "access"));

        assertThat(response.getStatusCode().value()).isEqualTo(200);
        assertThat(response.getBody()).containsOnlyKeys("sub");
    }

    @Test
    @DisplayName("The email scope releases the email, and only the email")
    void email_scope_releases_email() {
        var response = call(token("openid email", "access"));

        assertThat(response.getBody()).containsOnlyKeys("sub", "email");
        assertThat(response.getBody().get("email")).isEqualTo("alice@leap.test");
    }

    @Test
    @DisplayName("The profile scope releases name and picture, but not email")
    void profile_scope_releases_profile() {
        var response = call(token("openid profile", "access"));

        assertThat(response.getBody()).containsOnlyKeys("sub", "name", "picture");
    }

    @Test
    @DisplayName("A revoked access token is refused, as introspection already did")
    void revoked_token_is_refused() {
        when(revocationRepository.existsByTokenHash(anyString())).thenReturn(true);

        var response = call(token("openid email", "access"));

        assertThat(response.getStatusCode().value()).isEqualTo(401);
        assertThat(response.getHeaders().getFirst(HttpHeaders.WWW_AUTHENTICATE))
                .contains("error=\"invalid_token\"");
    }

    @Test
    @DisplayName("An ID token is still refused, and now says why")
    void id_token_is_refused_with_a_challenge() {
        var response = call(token("openid", "id"));

        assertThat(response.getStatusCode().value()).isEqualTo(401);
        assertThat(response.getHeaders().getFirst(HttpHeaders.WWW_AUTHENTICATE))
                .contains("Bearer", "error=\"invalid_token\"");
    }

    @Test
    @DisplayName("No Authorization header challenges without an error code")
    void missing_token_challenges_without_error_code() {
        var response = call(null);

        assertThat(response.getStatusCode().value()).isEqualTo(401);
        String challenge = response.getHeaders().getFirst(HttpHeaders.WWW_AUTHENTICATE);
        // RFC 6750 §3: no error code when no credentials were presented --
        // nothing was wrong with a token, there wasn't one.
        assertThat(challenge).startsWith("Bearer").doesNotContain("error=");
    }

    @Test
    @DisplayName("A garbage token challenges rather than returning a bare 401")
    void malformed_token_challenges() {
        var response = call("not-a-jwt");

        assertThat(response.getStatusCode().value()).isEqualTo(401);
        assertThat(response.getHeaders().getFirst(HttpHeaders.WWW_AUTHENTICATE))
                .contains("error=\"invalid_token\"");
    }

    @Test
    @DisplayName("A token with no scope claim releases only the subject")
    void absent_scope_releases_nothing_extra() {
        // Legacy tokens minted before scope was recorded must not be treated as
        // "all scopes" -- failing open here would defeat the whole story.
        var response = call(token(null, "access"));

        assertThat(response.getBody()).containsOnlyKeys("sub");
    }
}
