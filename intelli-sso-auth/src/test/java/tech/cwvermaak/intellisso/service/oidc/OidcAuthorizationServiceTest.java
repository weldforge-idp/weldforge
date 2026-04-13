package tech.cwvermaak.intellisso.service.oidc;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import tech.cwvermaak.intellisso.model.OAuthAuthorizationCode;
import tech.cwvermaak.intellisso.model.OidcClient;
import tech.cwvermaak.intellisso.model.Tenant;
import tech.cwvermaak.intellisso.model.User;
import tech.cwvermaak.intellisso.repository.OAuthAuthorizationCodeRepository;
import tech.cwvermaak.intellisso.repository.OidcClientRepository;
import tech.cwvermaak.intellisso.service.audit.AuditService;
import tech.cwvermaak.intellisso.service.oidc.OidcAuthorizationService.AuthorizeRequest;
import tech.cwvermaak.intellisso.service.oidc.OidcAuthorizationService.CodeExchangeRequest;
import tech.cwvermaak.intellisso.service.oidc.OidcAuthorizationService.CodeExchangeResult;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicLong;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/**
 * Contract tests for the OIDC authorization service. Pure unit tests with
 * Mockito-backed repos — no DB, no Spring context. The PKCE happy path,
 * the verifier mismatch, and code reuse all live here.
 */
class OidcAuthorizationServiceTest {

    private OidcClientRepository clientRepo;
    private OAuthAuthorizationCodeRepository codeRepo;
    private AuditService auditService;
    private OidcAuthorizationService service;

    private Tenant tenant;
    private User user;
    private OidcClient client;
    private final Map<String, OAuthAuthorizationCode> codeStore = new HashMap<>();
    private final AtomicLong idSeq = new AtomicLong(1);

    @BeforeEach
    void setUp() {
        clientRepo = mock(OidcClientRepository.class);
        codeRepo = mock(OAuthAuthorizationCodeRepository.class);
        auditService = mock(AuditService.class);
        service = new OidcAuthorizationService(clientRepo, codeRepo, auditService);

        tenant = Tenant.builder().id(1L).slug("acme").name("Acme").build();
        user = User.builder().id(42L).tenant(tenant).email("alice@acme.test").build();

        client = OidcClient.builder()
                .id(10L)
                .tenant(tenant)
                .clientId("acme-app")
                .clientSecret("super-secret")
                .redirectUris("https://app.acme.test/callback")
                .scopes("openid profile email")
                .grantTypes("authorization_code client_credentials")
                .requirePkce(true)
                .build();
        when(clientRepo.findByTenantIdAndClientId(1L, "acme-app")).thenReturn(Optional.of(client));

        when(codeRepo.save(any(OAuthAuthorizationCode.class))).thenAnswer(inv -> {
            OAuthAuthorizationCode row = inv.getArgument(0);
            if (row.getId() == null) row.setId(idSeq.getAndIncrement());
            if (row.getCreatedAt() == null) row.setCreatedAt(java.time.LocalDateTime.now());
            codeStore.put(row.getCodeHash(), row);
            return row;
        });
        when(codeRepo.findByCodeHash(any())).thenAnswer(inv ->
                Optional.ofNullable(codeStore.get((String) inv.getArgument(0))));
    }

    private AuthorizeRequest validRequest(String challenge) {
        return new AuthorizeRequest("acme-app",
                "https://app.acme.test/callback",
                List.of("openid", "email"),
                "state-xyz", "nonce-abc", challenge, "S256");
    }

    @Test
    @DisplayName("issueAuthorizationCode returns a fresh code and persists it")
    void issueCode_happyPath() {
        String verifier = "verifier-1234567890abcdef";
        String challenge = OidcAuthorizationService.base64UrlSha256(verifier);

        String code = service.issueAuthorizationCode(tenant, user, validRequest(challenge));

        assertThat(code).isNotBlank();
        assertThat(codeStore).hasSize(1);
        verify(auditService).recordUserAction(eq(OidcAuthorizationService.OIDC_CODE_ISSUED),
                eq(user), any(), any(), any());
    }

    @Test
    @DisplayName("authorize rejects an unknown redirect_uri")
    void issueCode_redirectMismatch() {
        AuthorizeRequest bad = new AuthorizeRequest("acme-app",
                "https://evil.test/callback", List.of("openid"),
                "s", "n", "challenge", "S256");
        assertThatThrownBy(() -> service.issueAuthorizationCode(tenant, user, bad))
                .isInstanceOf(OidcAuthorizationException.class)
                .satisfies(e -> assertThat(((OidcAuthorizationException) e).getErrorCode())
                        .isEqualTo("invalid_request"));
    }

    @Test
    @DisplayName("authorize rejects a missing code_challenge when PKCE is required")
    void issueCode_pkceRequired() {
        AuthorizeRequest noPkce = new AuthorizeRequest("acme-app",
                "https://app.acme.test/callback", List.of("openid"),
                "s", "n", null, null);
        assertThatThrownBy(() -> service.issueAuthorizationCode(tenant, user, noPkce))
                .isInstanceOf(OidcAuthorizationException.class);
    }

    @Test
    @DisplayName("exchangeCode returns the user + scopes when verifier matches")
    void exchange_happyPath() {
        String verifier = "verifier-1234567890abcdef";
        String challenge = OidcAuthorizationService.base64UrlSha256(verifier);
        String code = service.issueAuthorizationCode(tenant, user, validRequest(challenge));

        CodeExchangeRequest req = new CodeExchangeRequest(
                code, "acme-app", "super-secret",
                "https://app.acme.test/callback", verifier);

        CodeExchangeResult result = service.exchangeCode(tenant, req);

        assertThat(result.user()).isEqualTo(user);
        assertThat(result.client()).isEqualTo(client);
        assertThat(result.scopes()).contains("openid", "email");
        assertThat(result.nonce()).isEqualTo("nonce-abc");

        // Code is now used.
        OAuthAuthorizationCode row = codeStore.values().iterator().next();
        assertThat(row.getUsedAt()).isNotNull();
    }

    @Test
    @DisplayName("exchangeCode rejects a wrong PKCE verifier")
    void exchange_pkceMismatch() {
        String challenge = OidcAuthorizationService.base64UrlSha256("right-verifier");
        String code = service.issueAuthorizationCode(tenant, user, validRequest(challenge));

        CodeExchangeRequest wrong = new CodeExchangeRequest(
                code, "acme-app", "super-secret",
                "https://app.acme.test/callback", "wrong-verifier");

        assertThatThrownBy(() -> service.exchangeCode(tenant, wrong))
                .isInstanceOf(OidcAuthorizationException.class)
                .satisfies(e -> assertThat(((OidcAuthorizationException) e).getErrorCode())
                        .isEqualTo("invalid_grant"));
    }

    @Test
    @DisplayName("exchangeCode rejects a code that has already been used")
    void exchange_codeReuse() {
        String verifier = "verifier-abcdef1234567890";
        String challenge = OidcAuthorizationService.base64UrlSha256(verifier);
        String code = service.issueAuthorizationCode(tenant, user, validRequest(challenge));

        CodeExchangeRequest first = new CodeExchangeRequest(
                code, "acme-app", "super-secret",
                "https://app.acme.test/callback", verifier);
        service.exchangeCode(tenant, first);

        // Second presentation must be rejected.
        assertThatThrownBy(() -> service.exchangeCode(tenant, first))
                .isInstanceOf(OidcAuthorizationException.class)
                .hasMessageContaining("already used");
    }

    @Test
    @DisplayName("exchangeCode rejects a code from a different tenant")
    void exchange_crossTenant() {
        String verifier = "verifier-abcdef1234567890";
        String challenge = OidcAuthorizationService.base64UrlSha256(verifier);
        String code = service.issueAuthorizationCode(tenant, user, validRequest(challenge));

        Tenant otherTenant = Tenant.builder().id(2L).slug("globex").name("Globex").build();
        CodeExchangeRequest req = new CodeExchangeRequest(
                code, "acme-app", "super-secret",
                "https://app.acme.test/callback", verifier);

        assertThatThrownBy(() -> service.exchangeCode(otherTenant, req))
                .isInstanceOf(OidcAuthorizationException.class)
                .hasMessageContaining("does not belong to this tenant");
    }

    @Test
    @DisplayName("client credentials grant requires the right secret and the right grant type")
    void clientCredentials_happyAndUnhappy() {
        OidcClient verified = service.verifyClientCredentials(tenant, "acme-app", "super-secret");
        assertThat(verified).isEqualTo(client);

        assertThatThrownBy(() -> service.verifyClientCredentials(tenant, "acme-app", "nope"))
                .isInstanceOf(OidcAuthorizationException.class);
    }
}
