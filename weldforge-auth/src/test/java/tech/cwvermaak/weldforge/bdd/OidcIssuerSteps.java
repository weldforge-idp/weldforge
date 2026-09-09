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

    // Conformance-programme state. The refresh store is a real in-memory
    // implementation rather than a stub: the behaviour under test IS the
    // storage (which family a token belongs to, whether it is revoked), so a
    // stub that always answered would assert nothing.
    private tech.cwvermaak.weldforge.repository.RefreshTokenRepository refreshRepo;
    private tech.cwvermaak.weldforge.service.security.RefreshTokenFamilyRevoker familyRevoker;
    private tech.cwvermaak.weldforge.service.security.RefreshTokenService refreshTokenService;
    private final Map<String, tech.cwvermaak.weldforge.model.RefreshToken> refreshStore = new HashMap<>();
    private String rawRefreshToken;
    private java.util.UUID firstFamilyId;
    private java.time.Instant authTime;
    private tech.cwvermaak.weldforge.repository.MfaFactorRepository mfaFactorRepo;
    private tech.cwvermaak.weldforge.repository.OidcConsentGrantRepository consentRepo;
    private final Map<String, tech.cwvermaak.weldforge.model.OidcConsentGrant> consentStore = new HashMap<>();
    private Boolean standingConsentApplies;
    private boolean stepUpRequired;

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
        // recordIssuedFamily looks codes up by primary key, not by hash. Without
        // this the family link is silently never recorded and a code replay
        // revokes nothing -- which is the whole behaviour under test.
        when(codeRepo.findById(any())).thenAnswer(inv -> {
            Long wanted = inv.getArgument(0);
            return codeStore.values().stream()
                    .filter(row -> wanted.equals(row.getId()))
                    .findFirst();
        });

        signingKeyService = new TenantSigningKeyService(signingKeyRepo);
        mfaFactorRepo = mock(tech.cwvermaak.weldforge.repository.MfaFactorRepository.class);
        consentRepo = mock(tech.cwvermaak.weldforge.repository.OidcConsentGrantRepository.class);
        when(consentRepo.findByUserIdAndClientId(any(), any())).thenAnswer(inv ->
                Optional.ofNullable(consentStore.get(inv.getArgument(0) + ":" + inv.getArgument(1))));
        var mfaPolicyService = mock(tech.cwvermaak.weldforge.service.TenantMfaPolicyService.class);
        // Default: no policy, no verified factors — step-up only fires if require_mfa is set.
        when(mfaPolicyService.effectivePolicy(anyLong())).thenReturn(
                tech.cwvermaak.weldforge.model.TenantMfaPolicy.builder()
                        .enforcement(tech.cwvermaak.weldforge.model.TenantMfaPolicy.Enforcement.OPTIONAL)
                        .defaultStepupMaxAge(0)
                        .build());
        refreshRepo = mock(tech.cwvermaak.weldforge.repository.RefreshTokenRepository.class);
        when(refreshRepo.save(any(tech.cwvermaak.weldforge.model.RefreshToken.class))).thenAnswer(inv -> {
            tech.cwvermaak.weldforge.model.RefreshToken row = inv.getArgument(0);
            if (row.getId() == null) row.setId(idSeq.getAndIncrement());
            refreshStore.put(row.getTokenHash(), row);
            return row;
        });
        when(refreshRepo.findByTokenHash(any())).thenAnswer(inv ->
                Optional.ofNullable(refreshStore.get((String) inv.getArgument(0))));
        // Revoking a family marks every row carrying that family id, which is
        // what the assertions read back.
        familyRevoker = mock(tech.cwvermaak.weldforge.service.security.RefreshTokenFamilyRevoker.class);
        when(familyRevoker.revoke(any(), any())).thenAnswer(inv -> {
            java.util.UUID family = inv.getArgument(0);
            int count = 0;
            for (var row : refreshStore.values()) {
                if (family.equals(row.getFamilyId()) && row.getRevokedAt() == null) {
                    row.setRevokedAt(java.time.LocalDateTime.now());
                    count++;
                }
            }
            return count;
        });

        authorizationService = new OidcAuthorizationService(clientRepo, codeRepo, auditService,
                new io.micrometer.core.instrument.simple.SimpleMeterRegistry(), familyRevoker,
                mfaFactorRepo, mfaPolicyService);
        tokenService = new OidcTokenService(signingKeyService, new SimpleMeterRegistry());
        // Set @Value-injected lifetimes since we constructed the bean by hand.
        ReflectionTestUtils.setField(tokenService, "accessTokenSeconds", 3600L);
        ReflectionTestUtils.setField(tokenService, "idTokenSeconds", 3600L);
        introspectionService = new OidcIntrospectionService(signingKeyService, revocationRepo);
        revocationService = new OidcRevocationService(signingKeyService, revocationRepo, auditService,
                refreshRepo, familyRevoker);

        var refreshProperties = new tech.cwvermaak.weldforge.service.security.RefreshTokenProperties();
        refreshTokenService = new tech.cwvermaak.weldforge.service.security.RefreshTokenService(
                refreshRepo, familyRevoker, refreshProperties, auditService);
    }

    private Map<String, Object> lastIntrospection;

    @When("the access token is introspected at tenant {string}")
    public void introspectAccessToken(String slug) {
        Tenant t = "acme".equals(slug) ? acme : globex;
        lastIntrospection = introspectionService.introspect(
                lastIssued.accessToken(), t, "https://weldforge.test/t/" + t.getSlug(), null);
    }

    @When("the token {string} is introspected at tenant {string}")
    public void introspectArbitraryToken(String token, String slug) {
        Tenant t = "acme".equals(slug) ? acme : globex;
        lastIntrospection = introspectionService.introspect(
                token, t, "https://weldforge.test/t/" + t.getSlug(), null);
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
        // Distinct ids: a shared id would make every client-binding check pass
        // by accident, which is exactly what the cross-client revocation
        // scenario is supposed to catch.
        acmeApp = OidcClient.builder()
                .id(idSeq.getAndIncrement())
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
        // Drives the REAL controller rather than rebuilding the document here.
        // A hand-rolled copy would assert only that the test agrees with itself
        // -- and drift between the document and the server is precisely the
        // defect CONF-4.2 exists to prevent.
        var tenantRepo = mock(tech.cwvermaak.weldforge.repository.TenantRepository.class);
        when(tenantRepo.findBySlug(slug)).thenReturn(Optional.of(
                "globex".equals(slug) ? globex : acme));
        var controller = new tech.cwvermaak.weldforge.controller.OidcDiscoveryController(
                tenantRepo, signingKeyService);

        var request = new org.springframework.mock.web.MockHttpServletRequest(
                "GET", "/t/" + slug + "/.well-known/openid-configuration");
        request.setScheme("https");
        request.setServerName("weldforge.test");
        request.setServerPort(443);

        Map<String, Object> doc = new java.util.LinkedHashMap<>(
                controller.discovery(slug, request).getBody());
        // The JWKS is served from its own endpoint; fetch it through the same
        // controller so the existing key assertions still describe live output.
        doc.put("jwks", controller.jwks(slug).getBody());
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

    /** The client the most recent authorization was issued to. */
    private String authorizedClientId = "acme-app";

    @When("alice authorizes {string} for scope {string}")
    public void aliceAuthorizes(String clientId, String scope) {
        authorizedClientId = clientId;
        AuthorizeRequest req = new AuthorizeRequest(
                clientId,
                "https://app.acme.test/callback",
                java.util.Arrays.stream(scope.split("\\s+")).toList(),
                "state", "nonce-123", challenge, "S256",
                null, authTime, null);
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
                    new CodeExchangeRequest(issuedCode, authorizedClientId, "super-secret",
                            "https://app.acme.test/callback", verifierToUse));
            lastScopes = result.scopes();
            lastNonce = result.nonce();
            lastIssued = tokenService.issueForCodeExchange(
                    tenantToExchangeAt, result.client(), result.user(),
                    lastScopes, lastNonce, "https://weldforge.test/t/" + tenantToExchangeAt.getSlug(),
                    result.amr(), result.authTime());

            // Mint the refresh family the same way the token endpoint does, and
            // record it on the code -- that link is what lets a later replay
            // revoke what the first exchange produced (CONF-1.2).
            var issuedRefresh = refreshTokenService.issueNewForClient(
                    result.user(), result.client(), null, null, null,
                    String.join(" ", lastScopes));
            rawRefreshToken = issuedRefresh.rawToken();
            if (firstFamilyId == null) firstFamilyId = issuedRefresh.row().getFamilyId();
            authorizationService.recordIssuedFamily(result.codeId(), issuedRefresh.row().getFamilyId());
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

    // ---- Standards-conformance programme steps ------------------------

    @Given("client {string} is registered for scopes {string}")
    public void clientRegisteredForScopes(String clientId, String scopes) {
        OidcClient client = clientRepo.findByTenantIdAndClientId(acme.getId(), clientId).orElseThrow();
        client.setScopes(scopes);
    }

    @When("the resulting refresh token is exchanged")
    public void refreshExchanged() {
        refreshExchangedRequesting(null);
    }

    @When("the refresh token is exchanged requesting scope {string}")
    public void refreshExchangedRequesting(String requestedScope) {
        try {
            OidcClient client = refreshStore.get(
                    tech.cwvermaak.weldforge.service.security.RefreshTokenService.hash(rawRefreshToken))
                    .getClient();
            var rotated = refreshTokenService.rotateForClient(rawRefreshToken, client, null, null);
            rawRefreshToken = rotated.rawToken();

            // Mirrors OidcAuthorizationController.resolveRefreshScopes: the
            // family's recorded grant is the ceiling, and a requested scope may
            // narrow it but never widen past it.
            String granted = rotated.row().getGrantedScopes();
            List<String> ceiling = granted == null || granted.isBlank()
                    ? client.getScopeList()
                    : java.util.Arrays.stream(granted.split("\\s+")).filter(x -> !x.isBlank()).toList();
            if (requestedScope == null) {
                lastScopes = ceiling;
            } else {
                List<String> requested = java.util.Arrays.stream(requestedScope.split("\\s+"))
                        .filter(x -> !x.isBlank()).toList();
                for (String one : requested) {
                    if (!ceiling.contains(one)) {
                        throw new OidcAuthorizationException("invalid_scope",
                                "Scope '" + one + "' was not granted to this refresh token");
                    }
                }
                lastScopes = requested;
            }
            world.lastError = null;
        } catch (OidcAuthorizationException e) {
            world.lastError = e;
        }
    }

    @Then("the issued scopes are {string}")
    public void issuedScopesAre(String expected) {
        assertThat(world.lastError).isNull();
        assertThat(lastScopes)
                .containsExactlyInAnyOrderElementsOf(java.util.Arrays.asList(expected.split("\\s+")));
    }

    @When("the same code is exchanged a second time")
    public void sameCodeExchangedTwice() {
        exchangeWith(verifier, acme);
    }

    @Then("the refresh token family from the first exchange is revoked")
    public void familyIsRevoked() {
        assertThat(firstFamilyId).as("no refresh family was recorded").isNotNull();
        assertThat(refreshStore.values())
                .filteredOn(row -> firstFamilyId.equals(row.getFamilyId()))
                .isNotEmpty()
                .allSatisfy(row -> assertThat(row.getRevokedAt()).isNotNull());
    }

    @Then("the refresh token family from the first exchange is still active")
    public void familyIsActive() {
        assertThat(firstFamilyId).isNotNull();
        assertThat(refreshStore.values())
                .filteredOn(row -> firstFamilyId.equals(row.getFamilyId()))
                .isNotEmpty()
                .allSatisfy(row -> assertThat(row.getRevokedAt()).isNull());
    }

    @When("the refresh token is revoked by client {string}")
    public void refreshRevokedByClient(String clientId) {
        OidcClient caller = clientRepo.findByTenantIdAndClientId(acme.getId(), clientId).orElseThrow();
        revocationService.revoke(rawRefreshToken, acme, caller,
                "https://weldforge.test/t/" + acme.getSlug());
    }

    @Then("the discovery document advertises issuer identification")
    public void discoveryAdvertisesIss() {
        assertThat(lastDiscovery.get("authorization_response_iss_parameter_supported")).isEqualTo(true);
    }

    @SuppressWarnings("unchecked")
    @Then("the discovery document lists grant type {string}")
    public void discoveryListsGrant(String grant) {
        assertThat((List<String>) lastDiscovery.get("grant_types_supported")).contains(grant);
    }

    @Then("the discovery document advertises a registration endpoint")
    public void discoveryHasRegistration() {
        assertThat((String) lastDiscovery.get("registration_endpoint")).endsWith("/oauth2/register");
    }

    @SuppressWarnings("unchecked")
    @Then("the discovery document lists auth method {string}")
    public void discoveryListsAuthMethod(String method) {
        assertThat((List<String>) lastDiscovery.get("token_endpoint_auth_methods_supported"))
                .contains(method);
    }

    // ---- Sprint 4: OIDC Core request parameters -----------------------

    @Given("alice authenticated {int} minutes ago")
    public void aliceAuthenticatedMinutesAgo(int minutes) {
        authTime = java.time.Instant.now().minusSeconds(minutes * 60L);
    }

    @Given("alice's authentication time is unknown")
    public void aliceAuthTimeUnknown() {
        authTime = null;
    }

    private Claims idTokenClaims() {
        TenantSigningKey key = signingKeyService.getOrCreateActive(acme);
        RSAPublicKey pub = signingKeyService.loadPublicKey(key);
        return Jwts.parser().verifyWith(pub).build()
                .parseSignedClaims(lastIssued.idToken()).getPayload();
    }

    @Then("the ID token reports the authentication from {int} minutes ago")
    public void idTokenReportsAuthTime(int minutes) {
        long expected = java.time.Instant.now().minusSeconds(minutes * 60L).getEpochSecond();
        Number actual = idTokenClaims().get("auth_time", Number.class);
        assertThat(actual).isNotNull();
        // A couple of seconds of slack: the step and the assertion each read the
        // clock, and the claim is second-granular.
        assertThat(Math.abs(actual.longValue() - expected)).isLessThanOrEqualTo(5L);
    }

    @Then("the ID token's auth_time is earlier than its iat")
    public void authTimeBeforeIat() {
        Claims claims = idTokenClaims();
        assertThat(claims.get("auth_time", Number.class).longValue())
                .isLessThan(claims.getIssuedAt().toInstant().getEpochSecond());
    }

    @Then("the ID token has no auth_time claim")
    public void noAuthTimeClaim() {
        assertThat(idTokenClaims().get("auth_time")).isNull();
    }

    @Then("the ID token's at_hash matches the issued access token")
    public void atHashMatches() throws Exception {
        byte[] digest = java.security.MessageDigest.getInstance("SHA-256")
                .digest(lastIssued.accessToken().getBytes(java.nio.charset.StandardCharsets.US_ASCII));
        String expected = java.util.Base64.getUrlEncoder().withoutPadding()
                .encodeToString(java.util.Arrays.copyOf(digest, digest.length / 2));
        assertThat(idTokenClaims().get("at_hash")).isEqualTo(expected);
    }

    @Given("alice has already consented to {string} for scope {string}")
    public void aliceHasConsented(String clientId, String scope) {
        OidcClient client = clientRepo.findByTenantIdAndClientId(acme.getId(), clientId).orElseThrow();
        var grant = tech.cwvermaak.weldforge.model.OidcConsentGrant.builder()
                .tenantId(acme.getId())
                .userId(alice.getId())
                .clientId(client.getId())
                .scopes(tech.cwvermaak.weldforge.model.OidcConsentGrant.normalise(
                        java.util.Arrays.stream(scope.split("\\s+")).toList()))
                .grantedAt(java.time.LocalDateTime.now())
                .build();
        consentStore.put(alice.getId() + ":" + client.getId(), grant);
    }

    @When("alice's consent for {string} covering {string} is checked")
    public void consentIsChecked(String clientId, String scope) {
        OidcClient client = clientRepo.findByTenantIdAndClientId(acme.getId(), clientId).orElseThrow();
        standingConsentApplies = consentRepo
                .findByUserIdAndClientId(alice.getId(), client.getId())
                .map(g -> g.covers(java.util.Arrays.stream(scope.split("\\s+")).toList()))
                .orElse(false);
    }

    @Then("the standing consent applies")
    public void consentApplies() {
        assertThat(standingConsentApplies).isTrue();
    }

    @Then("the standing consent does not apply")
    public void consentDoesNotApply() {
        assertThat(standingConsentApplies).isFalse();
    }

    @Given("{string} requires MFA")
    public void clientRequiresMfa(String clientId) {
        clientRepo.findByTenantIdAndClientId(acme.getId(), clientId)
                .orElseThrow().setRequireMfa(true);
    }

    @Given("alice has a verified factor last used {int} minutes ago")
    public void aliceHasFactorLastUsed(int minutes) {
        var factor = tech.cwvermaak.weldforge.model.MfaFactor.builder()
                .user(alice)
                .type(tech.cwvermaak.weldforge.model.MfaFactorType.TOTP)
                .enabled(true)
                .verified(true)
                .lastUsedAt(java.time.LocalDateTime.now().minusMinutes(minutes))
                .build();
        when(mfaFactorRepo.findByUserIdAndEnabledTrueAndVerifiedTrue(alice.getId()))
                .thenReturn(List.of(factor));
    }

    @When("alice authorizes {string} for scope {string} with max_age {int}")
    public void aliceAuthorizesWithMaxAge(String clientId, String scope, int maxAge) {
        authorizedClientId = clientId;
        stepUpRequired = false;
        try {
            AuthorizeRequest req = new AuthorizeRequest(
                    clientId, "https://app.acme.test/callback",
                    java.util.Arrays.stream(scope.split("\\s+")).toList(),
                    "state", "nonce-123", challenge, "S256",
                    maxAge, authTime, null);
            issuedCode = authorizationService.issueAuthorizationCode(acme, alice, req);
            world.lastError = null;
        } catch (tech.cwvermaak.weldforge.service.oidc.StepUpRequiredException e) {
            stepUpRequired = true;
            issuedCode = null;
        }
    }

    @Then("a step-up challenge is required")
    public void stepUpIsRequired() {
        assertThat(stepUpRequired)
                .as("max_age was requested with a stale factor, so a fresh challenge is due")
                .isTrue();
    }

    @Then("an authorization code is issued without a step-up challenge")
    public void codeIssuedWithoutStepUp() {
        assertThat(stepUpRequired).isFalse();
        assertThat(issuedCode).isNotBlank();
    }
}
