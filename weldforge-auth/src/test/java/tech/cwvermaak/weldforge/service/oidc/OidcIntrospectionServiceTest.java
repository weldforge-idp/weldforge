package tech.cwvermaak.weldforge.service.oidc;

import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;
import tech.cwvermaak.weldforge.model.OidcClient;
import tech.cwvermaak.weldforge.model.Tenant;
import tech.cwvermaak.weldforge.model.TenantSigningKey;
import tech.cwvermaak.weldforge.model.User;
import tech.cwvermaak.weldforge.repository.RevokedOidcTokenRepository;
import tech.cwvermaak.weldforge.repository.TenantSigningKeyRepository;
import tech.cwvermaak.weldforge.service.oidc.OidcTokenService.IssuedTokens;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicLong;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

/**
 * Contract tests for the introspection service. We mint real RS256-signed
 * tokens via {@link OidcTokenService} so the verify path is exercised
 * end-to-end against the same tenant key the introspector publishes.
 */
class OidcIntrospectionServiceTest {

    private TenantSigningKeyRepository signingKeyRepo;
    private RevokedOidcTokenRepository revocationRepo;
    private TenantSigningKeyService signingKeyService;
    private OidcTokenService tokenService;
    private OidcIntrospectionService introspectionService;

    private Tenant acme;
    private OidcClient client;
    private User alice;
    private final List<TenantSigningKey> signingKeyStore = new ArrayList<>();
    private final Set<String> revokedHashes = new HashSet<>();

    @BeforeEach
    void setUp() {
        signingKeyRepo = mock(TenantSigningKeyRepository.class);
        revocationRepo = mock(RevokedOidcTokenRepository.class);

        AtomicLong idSeq = new AtomicLong(1);
        when(signingKeyRepo.save(any(TenantSigningKey.class))).thenAnswer(inv -> {
            TenantSigningKey k = inv.getArgument(0);
            if (k.getId() == null) {
                k.setId(idSeq.getAndIncrement());
                if (k.getCreatedAt() == null) k.setCreatedAt(java.time.LocalDateTime.now());
                signingKeyStore.add(k);
            }
            return k;
        });
        when(signingKeyRepo.findFirstByTenantIdAndActiveTrue(any())).thenAnswer(inv ->
                signingKeyStore.stream()
                        .filter(k -> k.getTenant().getId().equals(inv.getArgument(0))
                                  && Boolean.TRUE.equals(k.getActive()))
                        .findFirst());
        when(signingKeyRepo.findByKid(anyString())).thenAnswer(inv ->
                signingKeyStore.stream()
                        .filter(k -> k.getKid().equals(inv.getArgument(0)))
                        .findFirst());
        when(signingKeyRepo.findByTenantId(any())).thenAnswer(inv ->
                signingKeyStore.stream()
                        .filter(k -> k.getTenant().getId().equals(inv.getArgument(0)))
                        .toList());

        when(revocationRepo.existsByTokenHash(anyString())).thenAnswer(inv ->
                revokedHashes.contains((String) inv.getArgument(0)));

        signingKeyService = new TenantSigningKeyService(signingKeyRepo);
        tokenService = new OidcTokenService(signingKeyService, new SimpleMeterRegistry());
        ReflectionTestUtils.setField(tokenService, "accessTokenSeconds", 3600L);
        ReflectionTestUtils.setField(tokenService, "idTokenSeconds", 3600L);
        introspectionService = new OidcIntrospectionService(signingKeyService, revocationRepo);

        acme = Tenant.builder().id(1L).slug("acme").name("Acme").build();
        client = OidcClient.builder()
                .id(10L).tenant(acme).clientId("acme-app")
                .clientSecret("super-secret")
                .scopes("openid email").grantTypes("authorization_code")
                .redirectUris("https://app.acme.test/callback")
                .requirePkce(true).build();
        alice = User.builder().id(42L).tenant(acme).email("alice@acme.test").build();
    }

    @Test
    @DisplayName("a freshly minted token introspects as active with the standard claims")
    void freshToken_isActive() {
        IssuedTokens tokens = tokenService.issueForCodeExchange(
                acme, client, alice, List.of("openid", "email"),
                "nonce-1", "https://weldforge.test/t/acme");

        Map<String, Object> result = introspectionService.introspect(
                tokens.accessToken(), acme, "https://weldforge.test/t/acme");

        assertThat(result).containsEntry("active", true);
        assertThat(result).containsEntry("client_id", "acme-app");
        assertThat(result).containsEntry("sub", "42");
        assertThat(result.get("scope")).isEqualTo("openid email");
        assertThat(result).containsKey("exp");
    }

    @Test
    @DisplayName("a token whose issuer doesn't match the tenant returns inactive")
    void wrongIssuer_isInactive() {
        IssuedTokens tokens = tokenService.issueForCodeExchange(
                acme, client, alice, List.of("openid"), null,
                "https://weldforge.test/t/acme");

        Map<String, Object> result = introspectionService.introspect(
                tokens.accessToken(), acme, "https://weldforge.test/t/globex");

        assertThat(result).containsEntry("active", false);
    }

    @Test
    @DisplayName("a revoked token introspects as inactive")
    void revokedToken_isInactive() {
        IssuedTokens tokens = tokenService.issueForCodeExchange(
                acme, client, alice, List.of("openid"), null,
                "https://weldforge.test/t/acme");
        revokedHashes.add(OidcIntrospectionService.hash(tokens.accessToken()));

        Map<String, Object> result = introspectionService.introspect(
                tokens.accessToken(), acme, "https://weldforge.test/t/acme");

        assertThat(result).containsEntry("active", false);
    }

    @Test
    @DisplayName("garbage input returns inactive without throwing")
    void garbageToken_isInactive() {
        Map<String, Object> result = introspectionService.introspect(
                "not-a-jwt", acme, "https://weldforge.test/t/acme");
        assertThat(result).containsEntry("active", false);
    }

    @Test
    @DisplayName("null and empty tokens return inactive")
    void nullToken_isInactive() {
        assertThat(introspectionService.introspect(null, acme, "https://weldforge.test/t/acme"))
                .containsEntry("active", false);
        assertThat(introspectionService.introspect("", acme, "https://weldforge.test/t/acme"))
                .containsEntry("active", false);
    }

    @Test
    @DisplayName("an expired token introspects as inactive")
    void expiredToken_isInactive() {
        // Drop the lifetime to a negative number so the token is born expired.
        ReflectionTestUtils.setField(tokenService, "accessTokenSeconds", -1L);
        IssuedTokens tokens = tokenService.issueForCodeExchange(
                acme, client, alice, List.of("openid"), null,
                "https://weldforge.test/t/acme");

        Map<String, Object> result = introspectionService.introspect(
                tokens.accessToken(), acme, "https://weldforge.test/t/acme");

        assertThat(result).containsEntry("active", false);
    }
}
