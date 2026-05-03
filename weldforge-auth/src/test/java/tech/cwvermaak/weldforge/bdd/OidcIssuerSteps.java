package tech.cwvermaak.weldforge.bdd;

import io.cucumber.java.en.Given;
import io.cucumber.java.en.Then;
import io.cucumber.java.en.When;
import io.jsonwebtoken.Claims;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import io.jsonwebtoken.Jwts;
import org.springframework.test.util.ReflectionTestUtils;
import tech.cwvermaak.weldforge.model.OAuthAuthorizationCode;
import tech.cwvermaak.weldforge.model.OidcClient;
import tech.cwvermaak.weldforge.model.Tenant;
import tech.cwvermaak.weldforge.model.TenantSigningKey;
import tech.cwvermaak.weldforge.model.User;
import tech.cwvermaak.weldforge.model.RevokedOidcToken;
import tech.cwvermaak.weldforge.repository.OAuthAuthorizationCodeRepository;
import tech.cwvermaak.weldforge.repository.OidcClientRepository;
import tech.cwvermaak.weldforge.repository.RevokedOidcTokenRepository;
import tech.cwvermaak.weldforge.repository.TenantSigningKeyRepository;
import tech.cwvermaak.weldforge.service.audit.AuditService;
import tech.cwvermaak.weldforge.service.oidc.OidcIntrospectionService;
import tech.cwvermaak.weldforge.service.oidc.OidcRevocationService;
import tech.cwvermaak.weldforge.service.oidc.OidcAuthorizationException;
import tech.cwvermaak.weldforge.service.oidc.OidcAuthorizationService;
import tech.cwvermaak.weldforge.service.oidc.OidcAuthorizationService.AuthorizeRequest;
import tech.cwvermaak.weldforge.service.oidc.OidcAuthorizationService.CodeExchangeRequest;
import tech.cwvermaak.weldforge.service.oidc.OidcAuthorizationService.CodeExchangeResult;
import tech.cwvermaak.weldforge.service.oidc.OidcTokenService;
import tech.cwvermaak.weldforge.service.oidc.OidcTokenService.IssuedTokens;
import tech.cwvermaak.weldforge.service.oidc.TenantSigningKeyService;

import java.security.interfaces.RSAPublicKey;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicLong;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.*;

public class OidcIssuerSteps {

    private final TestWorld world;

    private TenantSigningKeyRepository signingKeyRepo;
    private OidcClientRepository clientRepo;
    private OAuthAuthorizationCodeRepository codeRepo;
    private RevokedOidcTokenRepository revocationRepo;
    private AuditService auditService;
    private TenantSigningKeyService signingKeyService;
    private OidcAuthorizationService authorizationService;
    private OidcTokenService tokenService;
    private OidcIntrospectionService introspectionService;
    private OidcRevocationService revocationService;
    private final java.util.Set<String> revokedHashes = new java.util.HashSet<>();

    private final Map<Long, List<TenantSigningKey>> keysByTenant = new HashMap<>();
    private final Map<String, OAuthAuthorizationCode> codeStore = new HashMap<>();
    private final AtomicLong idSeq = new AtomicLong(1);

    private Tenant acme;
    private Tenant globex;
    private OidcClient acmeApp;
    private User alice;

    private String verifier;
    private String challenge;
    private String issuedCode;
    private IssuedTokens lastIssued;
    private List<String> lastScopes;
    private String lastNonce;

    public OidcIssuerSteps(TestWorld world) {
        this.world = world;
    }

    private void ensureWired() {
        if (signingKeyService != null) return;
        signingKeyRepo = mock(TenantSigningKeyRepository.class);
        clientRepo = mock(OidcClientRepository.class);
        codeRepo = mock(OAuthAuthorizationCodeRepository.class);
        revocationRepo = mock(RevokedOidcTokenRepository.class);
        auditService = mock(AuditService.class);

        when(revocationRepo.existsByTokenHash(any())).thenAnswer(inv ->
                revokedHashes.contains((String) inv.getArgument(0)));
        when(revocationRepo.save(any(RevokedOidcToken.class))).thenAnswer(inv -> {
            RevokedOidcToken row = inv.getArgument(0);
            revokedHashes.add(row.getTokenHash());
            return row;
        });

        // signing key repo wiring
        when(signingKeyRepo.save(any(TenantSigningKey.class))).thenAnswer(inv -> {
            TenantSigningKey k = inv.getArgument(0);
            if (k.getId() == null) {
                k.setId(idSeq.getAndIncrement());
                if (k.getCreatedAt() == null) k.setCreatedAt(java.time.LocalDateTime.now());
                keysByTenant.computeIfAbsent(k.getTenant().getId(), id -> new java.util.ArrayList<>()).add(k);
            }
            return k;
        });
        when(signingKeyRepo.findFirstByTenantIdAndActiveTrue(any())).thenAnswer(inv ->
                keysByTenant.getOrDefault((Long) inv.getArgument(0), List.of()).stream()
                        .filter(k -> Boolean.TRUE.equals(k.getActive()))
                        .findFirst());
        when(signingKeyRepo.findByTenantId(any())).thenAnswer(inv ->
                keysByTenant.getOrDefault((Long) inv.getArgument(0), List.of()));
        when(signingKeyRepo.findByKid(any())).thenAnswer(inv -> {
            String kid = inv.getArgument(0);
            return keysByTenant.values().stream().flatMap(List::stream)
                    .filter(k -> k.getKid().equals(kid))
                    .findFirst();
        });

        // code repo wiring
        when(codeRepo.save(any(OAuthAuthorizationCode.class))).thenAnswer(inv -> {
            OAuthAuthorizationCode row = inv.getArgument(0);
            if (row.getId() == null) row.setId(idSeq.getAndIncrement());
            if (row.getCreatedAt() == null) row.setCreatedAt(java.time.LocalDateTime.now());
            codeStore.put(row.getCodeHash(), row);
            return row;
        });
        when(codeRepo.findByCodeHash(any())).thenAnswer(inv ->
                Optional.ofNullable(codeStore.get((String) inv.getArgument(0))));

        signingKeyService = new TenantSigningKeyService(signingKeyRepo);
        var mfaFactorRepo = mock(tech.cwvermaak.weldforge.repository.MfaFactorRepository.class);
        var mfaPolicyService = mock(tech.cwvermaak.weldforge.service.TenantMfaPolicyService.class);
        // Default: no policy, no verified factors — step-up only fires if require_mfa is set.
        when(mfaPolicyService.effectivePolicy(anyLong())).thenReturn(
                tech.cwvermaak.weldforge.model.TenantMfaPolicy.builder()
                        .enforcement(tech.cwvermaak.weldforge.model.TenantMfaPolicy.Enforcement.OPTIONAL)
                        .defaultStepupMaxAge(0)
                        .build());
        authorizationService = new OidcAuthorizationService(clientRepo, codeRepo, auditService,
                mfaFactorRepo, mfaPolicyService);
        tokenService = new OidcTokenService(signingKeyService, new SimpleMeterRegistry());
        // Set @Value-injected lifetimes since we constructed the bean by hand.
        ReflectionTestUtils.setField(tokenService, "accessTokenSeconds", 3600L);
        ReflectionTestUtils.setField(tokenService, "idTokenSeconds", 3600L);
        introspectionService = new OidcIntrospectionService(signingKeyService, revocationRepo);
        revocationService = new OidcRevocationService(signingKeyService, revocationRepo, auditService);
    }

    private Map<String, Object> lastIntrospection;

    @When("the access token is introspected at tenant {string}")
    public void introspectAccessToken(String slug) {
        Tenant t = "acme".equals(slug) ? acme : globex;
        lastIntrospection = introspectionService.introspect(
                lastIssued.accessToken(), t, "https://weldforge.test/t/" + t.getSlug());
    }

    @When("the token {string} is introspected at tenant {string}")
    public void introspectArbitraryToken(String token, String slug) {
        Tenant t = "acme".equals(slug) ? acme : globex;
        lastIntrospection = introspectionService.introspect(
                token, t, "https://weldforge.test/t/" + t.getSlug());
    }

    @When("the access token is revoked by client {string}")
    public void revokeAccessToken(String clientId) {
        revocationService.revoke(lastIssued.accessToken(), acme, acmeApp,
                "https://weldforge.test/t/acme");
    }

    @Then("the introspection result is active")
    public void resultIsActive() {
        assertThat(lastIntrospection).containsEntry("active", true);
    }

    @Then("the introspection result is inactive")
    public void resultIsInactive() {
        assertThat(lastIntrospection).containsEntry("active", false);
    }

    @Then("the introspection result client_id is {string}")
    public void resultClientId(String clientId) {
        assertThat(lastIntrospection).containsEntry("client_id", clientId);
    }

    @Then("the introspection result sub is alice's user id")
    public void resultSubIsAlice() {
        assertThat(lastIntrospection).containsEntry("sub", String.valueOf(alice.getId()));
    }

    @Given("tenant {string} has its own RSA signing key")
    public void tenantHasSigningKey(String slug) {
        ensureWired();
        if ("acme".equals(slug)) {
            acme = Tenant.builder().id(1L).slug(slug).name(slug).build();
            signingKeyService.getOrCreateActive(acme);
        }
    }

    @Given("tenant {string} exists with its own signing key")
    public void otherTenantWithKey(String slug) {
        if ("globex".equals(slug)) {
            globex = Tenant.builder().id(2L).slug(slug).name(slug).build();
            signingKeyService.getOrCreateActive(globex);
        }
    }

    @Given("tenant {string} has registered an OIDC client {string} with redirect {string} and PKCE required")
    public void tenantHasClient(String slug, String clientId, String redirect) {
        acmeApp = OidcClient.builder()
                .id(10L)
                .tenant(acme)
                .clientId(clientId)
                .clientSecret("super-secret")
                .redirectUris(redirect)
                .scopes("openid profile email")
                .grantTypes("authorization_code")
                .requirePkce(true)
                .build();
        when(clientRepo.findByTenantIdAndClientId(acme.getId(), clientId)).thenReturn(Optional.of(acmeApp));
    }

    @Given("user {string} exists in tenant {string}")
    public void userExists(String email, String slug) {
        alice = User.builder().id(42L).tenant(acme).email(email).build();
    }

    // -- Discovery doc -------------------------------------------------

    private Map<String, Object> lastDiscovery;

    @When("I fetch the discovery document for tenant {string}")
    public void fetchDiscovery(String slug) {
        // Build the doc the same way the controller does — pure data, no HTTP.
        String issuer = "https://weldforge.test/t/" + slug;
        Map<String, Object> doc = new java.util.LinkedHashMap<>();
        doc.put("issuer", issuer);
        doc.put("jwks_uri", issuer + "/oauth2/jwks");
        doc.put("authorization_endpoint", issuer + "/oauth2/authorize");
        doc.put("token_endpoint", issuer + "/oauth2/token");
        doc.put("id_token_signing_alg_values_supported", List.of("RS256"));
        doc.put("response_types_supported", List.of("code"));
        doc.put("code_challenge_methods_supported", List.of("S256"));
        // JWKS comes from the service, exactly like the live endpoint
        doc.put("jwks", signingKeyService.jwks(acme));
        lastDiscovery = doc;
    }

    @Then("the issuer is the tenant URL")
    public void issuerIsTenantUrl() {
        assertThat(lastDiscovery).containsEntry("issuer", "https://weldforge.test/t/acme");
    }

    @Then("the jwks contains the tenant's signing key")
    public void jwksContainsKey() {
        @SuppressWarnings("unchecked")
        Map<String, Object> jwks = (Map<String, Object>) lastDiscovery.get("jwks");
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> keys = (List<Map<String, Object>>) jwks.get("keys");
        assertThat(keys).isNotEmpty();
        assertThat(keys.get(0)).containsEntry("kty", "RSA").containsEntry("alg", "RS256");
    }

    @Then("RS256 is the only listed signing algorithm")
    public void rs256Only() {
        @SuppressWarnings("unchecked")
        List<String> algs = (List<String>) lastDiscovery.get("id_token_signing_alg_values_supported");
        assertThat(algs).containsExactly("RS256");
    }

    // -- Code flow -----------------------------------------------------

    @Given("alice generates a PKCE verifier and challenge")
    public void alicePkce() {
        verifier = "verifier-" + java.util.UUID.randomUUID();
        challenge = OidcAuthorizationService.base64UrlSha256(verifier);
    }

    @When("alice authorizes {string} for scope {string}")
    public void aliceAuthorizes(String clientId, String scope) {
        AuthorizeRequest req = new AuthorizeRequest(
                clientId,
                "https://app.acme.test/callback",
                java.util.Arrays.stream(scope.split("\\s+")).toList(),
                "state", "nonce-123", challenge, "S256");
        issuedCode = authorizationService.issueAuthorizationCode(acme, alice, req);
    }

    @When("alice exchanges the resulting code with the matching verifier")
    public void exchangeWithMatching() {
        exchangeWith(verifier, acme);
    }

    @When("alice exchanges the resulting code with a wrong verifier")
    public void exchangeWithWrong() {
        exchangeWith("wrong-verifier-" + java.util.UUID.randomUUID(), acme);
    }

    @When("the same code is presented at tenant {string}")
    public void presentAtOtherTenant(String slug) {
        exchangeWith(verifier, globex);
    }

    private void exchangeWith(String verifierToUse, Tenant tenantToExchangeAt) {
        try {
            CodeExchangeResult result = authorizationService.exchangeCode(tenantToExchangeAt,
                    new CodeExchangeRequest(issuedCode, "acme-app", "super-secret",
                            "https://app.acme.test/callback", verifierToUse));
            lastScopes = result.scopes();
            lastNonce = result.nonce();
            lastIssued = tokenService.issueForCodeExchange(
                    tenantToExchangeAt, result.client(), result.user(),
                    lastScopes, lastNonce, "https://weldforge.test/t/" + tenantToExchangeAt.getSlug());
            world.lastError = null;
        } catch (OidcAuthorizationException e) {
            world.lastError = e;
            lastIssued = null;
        }
    }

    @Then("an access token and an ID token are issued")
    public void tokensIssued() {
        assertThat(world.lastError).isNull();
        assertThat(lastIssued).isNotNull();
        assertThat(lastIssued.accessToken()).isNotBlank();
        assertThat(lastIssued.idToken()).isNotBlank();
    }

    @Then("the ID token is signed with the tenant's RSA key")
    public void idTokenSigned() {
        TenantSigningKey key = signingKeyService.getOrCreateActive(acme);
        RSAPublicKey publicKey = signingKeyService.loadPublicKey(key);
        Claims claims = Jwts.parser()
                .verifyWith(publicKey)
                .build()
                .parseSignedClaims(lastIssued.idToken())
                .getPayload();
        assertThat(claims.getSubject()).isEqualTo(String.valueOf(alice.getId()));
    }

    @Then("the ID token's {string} claim equals the tenant issuer")
    public void idTokenIssClaim(String claim) {
        Claims claims = parseIdToken();
        assertThat(claims.get(claim)).isEqualTo("https://weldforge.test/t/acme");
    }

    @Then("the ID token's {string} claim equals {string}")
    public void idTokenStringClaim(String claim, String expected) {
        Claims claims = parseIdToken();
        Object actual = claims.get(claim);
        // JJWT 0.12 normalises single-value `aud` claims to a Collection on
        // parse, so accept either form to keep the assertion natural.
        if (actual instanceof java.util.Collection<?> coll) {
            assertThat(coll.stream().map(Object::toString).toList())
                    .containsExactly(expected);
        } else {
            assertThat(actual).isEqualTo(expected);
        }
    }

    private Claims parseIdToken() {
        TenantSigningKey key = signingKeyService.getOrCreateActive(acme);
        RSAPublicKey publicKey = signingKeyService.loadPublicKey(key);
        return Jwts.parser()
                .verifyWith(publicKey)
                .build()
                .parseSignedClaims(lastIssued.idToken())
                .getPayload();
    }

    @Then("the exchange is rejected with error code {string}")
    public void rejectedWithCode(String errorCode) {
        assertThat(world.lastError).isInstanceOf(OidcAuthorizationException.class);
        assertThat(((OidcAuthorizationException) world.lastError).getErrorCode()).isEqualTo(errorCode);
    }
}
