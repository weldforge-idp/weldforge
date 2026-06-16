package tech.cwvermaak.weldforge.controller;

import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.ResponseEntity;
import org.springframework.test.util.ReflectionTestUtils;
import tech.cwvermaak.weldforge.model.OidcClient;
import tech.cwvermaak.weldforge.model.Tenant;
import tech.cwvermaak.weldforge.model.TenantSigningKey;
import tech.cwvermaak.weldforge.model.User;
import tech.cwvermaak.weldforge.repository.TenantRepository;
import tech.cwvermaak.weldforge.repository.TenantSigningKeyRepository;
import tech.cwvermaak.weldforge.repository.UserRepository;
import tech.cwvermaak.weldforge.service.oidc.OidcTokenService;
import tech.cwvermaak.weldforge.service.oidc.OidcTokenService.IssuedTokens;
import tech.cwvermaak.weldforge.service.oidc.TenantSigningKeyService;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicLong;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

/**
 * B-OIDC-3: userinfo must be called with an ACCESS token. An ID token (same
 * tenant key, but no token_type) must be rejected. Real RS256 tokens are minted
 * so the verify path runs end-to-end.
 */
class OidcUserinfoControllerTest {

    private TenantRepository tenantRepo;
    private UserRepository userRepo;
    private OidcTokenService tokenService;
    private OidcUserinfoController controller;

    private Tenant acme;
    private OidcClient client;
    private User alice;
    private static final String ISSUER = "https://weldforge.test/t/acme";

    @BeforeEach
    void setUp() {
        TenantSigningKeyRepository keyRepo = mock(TenantSigningKeyRepository.class);
        tenantRepo = mock(TenantRepository.class);
        userRepo = mock(UserRepository.class);

        List<TenantSigningKey> store = new ArrayList<>();
        AtomicLong idSeq = new AtomicLong(1);
        when(keyRepo.save(any(TenantSigningKey.class))).thenAnswer(inv -> {
            TenantSigningKey k = inv.getArgument(0);
            if (k.getId() == null) { k.setId(idSeq.getAndIncrement()); store.add(k); }
            return k;
        });
        when(keyRepo.findFirstByTenantIdAndActiveTrue(any())).thenAnswer(inv ->
                store.stream().filter(k -> k.getTenant().getId().equals(inv.getArgument(0))
                        && Boolean.TRUE.equals(k.getActive())).findFirst());
        when(keyRepo.findByKid(anyString())).thenAnswer(inv ->
                store.stream().filter(k -> k.getKid().equals(inv.getArgument(0))).findFirst());

        TenantSigningKeyService signingKeyService = new TenantSigningKeyService(keyRepo);
        tokenService = new OidcTokenService(signingKeyService, new SimpleMeterRegistry());
        ReflectionTestUtils.setField(tokenService, "accessTokenSeconds", 3600L);
        ReflectionTestUtils.setField(tokenService, "idTokenSeconds", 3600L);
        controller = new OidcUserinfoController(tenantRepo, userRepo, signingKeyService);

        acme = Tenant.builder().id(1L).slug("acme").name("Acme").build();
        client = OidcClient.builder().id(10L).tenant(acme).clientId("acme-app")
                .clientSecret("s").scopes("openid email").grantTypes("authorization_code")
                .redirectUris("https://app.acme.test/cb").requirePkce(true).build();
        alice = User.builder().id(42L).tenant(acme).email("alice@acme.test").name("Alice").build();

        when(tenantRepo.findBySlug("acme")).thenReturn(Optional.of(acme));
        when(userRepo.findById(42L)).thenReturn(Optional.of(alice));
    }

    private static HttpServletRequest bearer(String token) {
        HttpServletRequest r = mock(HttpServletRequest.class);
        when(r.getHeader("Authorization")).thenReturn("Bearer " + token);
        return r;
    }

    private IssuedTokens tokens() {
        return tokenService.issueForCodeExchange(acme, client, alice,
                List.of("openid", "email"), "n", ISSUER);
    }

    @Test
    @DisplayName("an access token is accepted and returns the user claims")
    void accessToken_ok() {
        ResponseEntity<Map<String, Object>> resp = controller.userinfo("acme", bearer(tokens().accessToken()));

        assertThat(resp.getStatusCode().value()).isEqualTo(200);
        assertThat(resp.getBody()).containsEntry("sub", "42").containsEntry("email", "alice@acme.test");
    }

    @Test
    @DisplayName("an ID token is rejected at userinfo (B-OIDC-3)")
    void idToken_rejected() {
        ResponseEntity<Map<String, Object>> resp = controller.userinfo("acme", bearer(tokens().idToken()));

        assertThat(resp.getStatusCode().value()).isEqualTo(401);
    }

    @Test
    @DisplayName("a missing/!Bearer Authorization header is 401")
    void noBearer_401() {
        HttpServletRequest r = mock(HttpServletRequest.class);
        when(r.getHeader("Authorization")).thenReturn(null);
        assertThat(controller.userinfo("acme", r).getStatusCode().value()).isEqualTo(401);
    }
}
