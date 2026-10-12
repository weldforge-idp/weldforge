package tech.cwvermaak.weldforge.service.oidc;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import tech.cwvermaak.weldforge.model.OAuthAuthorizationCode;
import tech.cwvermaak.weldforge.model.OidcClient;
import tech.cwvermaak.weldforge.model.Tenant;
import tech.cwvermaak.weldforge.model.User;
import tech.cwvermaak.weldforge.repository.OAuthAuthorizationCodeRepository;
import tech.cwvermaak.weldforge.repository.OidcClientRepository;
import tech.cwvermaak.weldforge.service.audit.AuditService;
import tech.cwvermaak.weldforge.service.oidc.OidcAuthorizationService.AuthorizeRequest;
import tech.cwvermaak.weldforge.service.oidc.OidcAuthorizationService.CodeExchangeRequest;
import tech.cwvermaak.weldforge.service.oidc.OidcAuthorizationService.CodeExchangeResult;

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
    private tech.cwvermaak.weldforge.service.security.RefreshTokenFamilyRevoker familyRevoker;
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

        // claim() is the conditional UPDATE the real repository performs, and an
        // unstubbed Mockito int is 0 -- which the service reads, correctly, as a
        // replay. Mirror the predicate so the happy path wins the claim and an
        // already-spent code loses it, which is how reuse now presents.
        when(codeRepo.claim(any(), any(java.time.LocalDateTime.class))).thenAnswer(inv -> {
            Long wanted = inv.getArgument(0);
            java.time.LocalDateTime now = inv.getArgument(1);
            for (tech.cwvermaak.weldforge.model.OAuthAuthorizationCode row : codeStore.values()) {
                if (wanted.equals(row.getId())) {
                    if (row.getUsedAt() != null) return 0;
                    row.setUsedAt(now);
                    return 1;
                }
            }
            return 0;
        });

        auditService = mock(AuditService.class);
        var mfaFactorRepo = mock(tech.cwvermaak.weldforge.repository.MfaFactorRepository.class);
        var mfaPolicyService = mock(tech.cwvermaak.weldforge.service.TenantMfaPolicyService.class);
        when(mfaPolicyService.effectivePolicy(org.mockito.ArgumentMatchers.anyLong())).thenReturn(
                tech.cwvermaak.weldforge.model.TenantMfaPolicy.builder()
                        .enforcement(tech.cwvermaak.weldforge.model.TenantMfaPolicy.Enforcement.OPTIONAL)
                        .defaultStepupMaxAge(0)
                        .build());
        familyRevoker =
                mock(tech.cwvermaak.weldforge.service.security.RefreshTokenFamilyRevoker.class);
        service = new OidcAuthorizationService(clientRepo, codeRepo, auditService,
                new io.micrometer.core.instrument.simple.SimpleMeterRegistry(), familyRevoker, mfaFactorRepo, mfaPolicyService);

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

    /**
     * RFC 8707 resource indicators.
     *
     * <p>The audience is the point of the whole feature, so these assert where
     * it ends up rather than only that a value was accepted. Opt-in is
     * asserted hardest: every client in production today has an empty
     * allow-list, and if the default ever stopped being "aud is the client id"
     * it would break every live relying party at once.
     */
    @org.junit.jupiter.api.Nested
    @DisplayName("resource indicators (RFC 8707)")
    class ResourceIndicators {

        private static final String MCP = "https://shot.cwvermaak.tech/mcp/counteract-studios";
        private static final String VERIFIER = "verifier-1234567890abcdef";

        private AuthorizeRequest withResource(String challenge, String resource) {
            return new AuthorizeRequest("acme-app", "https://app.acme.test/callback",
                    List.of("openid", "email"), "state-xyz", "nonce-abc",
                    challenge, "S256", null, null, null, resource);
        }

        private CodeExchangeRequest exchange(String code, String resource) {
            return new CodeExchangeRequest(code, "acme-app", "super-secret",
                    "https://app.acme.test/callback", VERIFIER, resource);
        }

        @Test
        @DisplayName("a client with no registered resource may not ask for one")
        void unregistered_resource_is_invalid_target() {
            String challenge = OidcAuthorizationService.base64UrlSha256(VERIFIER);

            assertThatThrownBy(() ->
                    service.issueAuthorizationCode(tenant, user, withResource(challenge, MCP)))
                    .isInstanceOf(OidcAuthorizationException.class)
                    .satisfies(e -> assertThat(((OidcAuthorizationException) e).getErrorCode())
                            .isEqualTo("invalid_target"));
        }

        @Test
        @DisplayName("asking for nothing is unchanged -- no resource is bound")
        void no_resource_binds_nothing() {
            String challenge = OidcAuthorizationService.base64UrlSha256(VERIFIER);

            String code = service.issueAuthorizationCode(tenant, user, validRequest(challenge));
            CodeExchangeResult result = service.exchangeCode(tenant, exchange(code, null));

            assertThat(result.resource())
                    .as("no resource means aud stays the client id, as it always has")
                    .isNull();
        }

        @Test
        @DisplayName("a registered resource is bound to the code and comes back on exchange")
        void registered_resource_round_trips() {
            client.setResources(MCP);
            String challenge = OidcAuthorizationService.base64UrlSha256(VERIFIER);

            String code = service.issueAuthorizationCode(tenant, user, withResource(challenge, MCP));
            CodeExchangeResult result = service.exchangeCode(tenant, exchange(code, MCP));

            assertThat(result.resource()).isEqualTo(MCP);
        }

        @Test
        @DisplayName("the token request may not redeem a code for a different resource")
        void token_request_cannot_switch_resource() {
            client.setResources(MCP + ",https://shot.cwvermaak.tech/api");
            String challenge = OidcAuthorizationService.base64UrlSha256(VERIFIER);
            String code = service.issueAuthorizationCode(tenant, user, withResource(challenge, MCP));

            // Both are registered to the client, so this is not the allow-list
            // check -- it is the binding. The user consented to one audience.
            assertThatThrownBy(() ->
                    service.exchangeCode(tenant, exchange(code, "https://shot.cwvermaak.tech/api")))
                    .isInstanceOf(OidcAuthorizationException.class)
                    .satisfies(e -> assertThat(((OidcAuthorizationException) e).getErrorCode())
                            .isEqualTo("invalid_target"));
        }

        @Test
        @DisplayName("omitting resource on the token request keeps the one already bound")
        void token_request_may_omit_resource() {
            client.setResources(MCP);
            String challenge = OidcAuthorizationService.base64UrlSha256(VERIFIER);
            String code = service.issueAuthorizationCode(tenant, user, withResource(challenge, MCP));

            CodeExchangeResult result = service.exchangeCode(tenant, exchange(code, null));

            assertThat(result.resource())
                    .as("RFC 8707 2.2: absent is not a request to drop the audience")
                    .isEqualTo(MCP);
        }

        @Test
        @DisplayName("case in scheme and host does not decide whether a resource is allowed")
        void scheme_and_host_are_case_insensitive() {
            client.setResources(MCP);
            String challenge = OidcAuthorizationService.base64UrlSha256(VERIFIER);

            // The canonical form is lower-case, and MCP asks servers to accept
            // upper-case anyway. The PATH is left alone: it is case-sensitive.
            String shouted = "HTTPS://SHOT.CWVERMAAK.TECH/mcp/counteract-studios";

            assertThat(service.issueAuthorizationCode(tenant, user, withResource(challenge, shouted)))
                    .isNotBlank();
        }

        @Test
        @DisplayName("a malformed resource is refused, and refused as invalid_target")
        void malformed_resources_are_invalid_target() {
            client.setResources(MCP);
            String challenge = OidcAuthorizationService.base64UrlSha256(VERIFIER);

            // RFC 8707 2: unparseable and unacceptable get the SAME error, so a
            // client cannot tell a bad URI from one it is not allowed to name.
            for (String bad : List.of(
                    "shot.cwvermaak.tech/mcp",
                    "https://shot.cwvermaak.tech/mcp#frag",
                    "/mcp/counteract-studios")) {
                assertThatThrownBy(() ->
                        service.issueAuthorizationCode(tenant, user, withResource(challenge, bad)))
                        .as("%s must be refused", bad)
                        .isInstanceOf(OidcAuthorizationException.class)
                        .satisfies(e -> assertThat(((OidcAuthorizationException) e).getErrorCode())
                                .isEqualTo("invalid_target"));
            }
        }

        @Test
        @DisplayName("normalisation lower-cases scheme and host, and nothing else")
        void normalisation_is_narrow() {
            assertThat(OidcAuthorizationService.normaliseResource(null)).isNull();
            assertThat(OidcAuthorizationService.normaliseResource("  ")).isNull();
            assertThat(OidcAuthorizationService.normaliseResource("HTTPS://Example.COM/Path"))
                    .as("path case is significant to the resource and is left alone")
                    .isEqualTo("https://example.com/Path");
            assertThat(OidcAuthorizationService.normaliseResource("https://example.com:8443/mcp"))
                    .isEqualTo("https://example.com:8443/mcp");
            assertThat(OidcAuthorizationService.normaliseResource("https://example.com/mcp/"))
                    .as("a trailing slash is not stripped -- it is part of the identifier")
                    .isEqualTo("https://example.com/mcp/");
        }
    }
}
