package tech.cwvermaak.intellisso.service.oidc;

import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.test.util.ReflectionTestUtils;
import tech.cwvermaak.intellisso.model.OidcClient;
import tech.cwvermaak.intellisso.model.RevokedOidcToken;
import tech.cwvermaak.intellisso.model.Tenant;
import tech.cwvermaak.intellisso.model.TenantSigningKey;
import tech.cwvermaak.intellisso.model.User;
import tech.cwvermaak.intellisso.repository.RevokedOidcTokenRepository;
import tech.cwvermaak.intellisso.repository.TenantSigningKeyRepository;
import tech.cwvermaak.intellisso.service.audit.AuditService;
import tech.cwvermaak.intellisso.service.oidc.OidcTokenService.IssuedTokens;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicLong;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

class OidcRevocationServiceTest {

    private TenantSigningKeyRepository signingKeyRepo;
    private RevokedOidcTokenRepository revocationRepo;
    private AuditService auditService;
    private TenantSigningKeyService signingKeyService;
    private OidcTokenService tokenService;
    private OidcRevocationService revocationService;

    private Tenant acme;
    private Tenant globex;
    private OidcClient client;
    private User alice;
    private final List<TenantSigningKey> store = new ArrayList<>();
    private final Set<String> hashes = new HashSet<>();

    @BeforeEach
    void setUp() {
        signingKeyRepo = mock(TenantSigningKeyRepository.class);
        revocationRepo = mock(RevokedOidcTokenRepository.class);
        auditService = mock(AuditService.class);

        AtomicLong idSeq = new AtomicLong(1);
        when(signingKeyRepo.save(any(TenantSigningKey.class))).thenAnswer(inv -> {
            TenantSigningKey k = inv.getArgument(0);
            if (k.getId() == null) {
                k.setId(idSeq.getAndIncrement());
                if (k.getCreatedAt() == null) k.setCreatedAt(java.time.LocalDateTime.now());
                store.add(k);
            }
            return k;
        });
        when(signingKeyRepo.findFirstByTenantIdAndActiveTrue(any())).thenAnswer(inv ->
                store.stream().filter(k -> k.getTenant().getId().equals(inv.getArgument(0))
                        && Boolean.TRUE.equals(k.getActive())).findFirst());
        when(signingKeyRepo.findByKid(anyString())).thenAnswer(inv ->
                store.stream().filter(k -> k.getKid().equals(inv.getArgument(0))).findFirst());
        when(signingKeyRepo.findByTenantId(any())).thenAnswer(inv ->
                store.stream().filter(k -> k.getTenant().getId().equals(inv.getArgument(0))).toList());

        when(revocationRepo.existsByTokenHash(anyString())).thenAnswer(inv ->
                hashes.contains((String) inv.getArgument(0)));
        when(revocationRepo.save(any(RevokedOidcToken.class))).thenAnswer(inv -> {
            RevokedOidcToken row = inv.getArgument(0);
            hashes.add(row.getTokenHash());
            return row;
        });

        signingKeyService = new TenantSigningKeyService(signingKeyRepo);
        tokenService = new OidcTokenService(signingKeyService, new SimpleMeterRegistry());
        ReflectionTestUtils.setField(tokenService, "accessTokenSeconds", 3600L);
        ReflectionTestUtils.setField(tokenService, "idTokenSeconds", 3600L);
        revocationService = new OidcRevocationService(signingKeyService, revocationRepo, auditService);

        acme = Tenant.builder().id(1L).slug("acme").name("Acme").build();
        globex = Tenant.builder().id(2L).slug("globex").name("Globex").build();
        client = OidcClient.builder()
                .id(10L).tenant(acme).clientId("acme-app")
                .clientSecret("super-secret")
                .scopes("openid email").grantTypes("authorization_code")
                .redirectUris("https://app.acme.test/callback")
                .requirePkce(true).build();
        alice = User.builder().id(42L).tenant(acme).email("alice@acme.test").build();
    }

    private IssuedTokens mintToken() {
        return tokenService.issueForCodeExchange(acme, client, alice, List.of("openid"),
                null, "https://weldforge.test/t/acme");
    }

    @Test
    @DisplayName("revoke persists the hash and writes an audit event")
    void revoke_persistsHashAndAudits() {
        IssuedTokens tokens = mintToken();

        revocationService.revoke(tokens.accessToken(), acme, client, "https://weldforge.test/t/acme");

        ArgumentCaptor<RevokedOidcToken> captor = ArgumentCaptor.forClass(RevokedOidcToken.class);
        verify(revocationRepo).save(captor.capture());
        RevokedOidcToken saved = captor.getValue();
        assertThat(saved.getTokenHash()).isEqualTo(OidcIntrospectionService.hash(tokens.accessToken()));
        assertThat(saved.getTenant()).isEqualTo(acme);
        assertThat(saved.getClient()).isEqualTo(client);
        assertThat(saved.getRevokedReason()).isEqualTo("client_request");

        verify(auditService).log(any());
    }

    @Test
    @DisplayName("revoke is idempotent — calling twice does not write a second row")
    void revoke_idempotent() {
        IssuedTokens tokens = mintToken();

        revocationService.revoke(tokens.accessToken(), acme, client, "https://weldforge.test/t/acme");
        revocationService.revoke(tokens.accessToken(), acme, client, "https://weldforge.test/t/acme");

        verify(revocationRepo, times(1)).save(any());
    }

    @Test
    @DisplayName("revoke silently drops a token whose issuer points at another tenant")
    void revoke_crossTenantIssuerIgnored() {
        IssuedTokens tokens = mintToken();

        // Caller pretends the token was issued by globex even though it
        // was actually minted by acme. The service must NOT write a row.
        revocationService.revoke(tokens.accessToken(), acme, client, "https://weldforge.test/t/globex");

        verify(revocationRepo, never()).save(any());
    }

    @Test
    @DisplayName("revoke silently drops a malformed token without raising")
    void revoke_garbageTokenSilent() {
        revocationService.revoke("not-a-jwt", acme, client, "https://weldforge.test/t/acme");
        verify(revocationRepo, never()).save(any());
    }

    @Test
    @DisplayName("revoke refuses a token that belongs to a different client_id")
    void revoke_wrongClientIgnored() {
        IssuedTokens tokens = mintToken();
        OidcClient otherClient = OidcClient.builder()
                .id(99L).tenant(acme).clientId("other-app")
                .clientSecret("nope")
                .scopes("openid").grantTypes("client_credentials")
                .redirectUris("https://other.test/cb")
                .requirePkce(false).build();

        revocationService.revoke(tokens.accessToken(), acme, otherClient, "https://weldforge.test/t/acme");

        verify(revocationRepo, never()).save(any());
    }
}
