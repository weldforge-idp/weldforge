package tech.cwvermaak.weldforge.bdd;

import io.cucumber.java.en.Given;
import io.cucumber.java.en.Then;
import io.cucumber.java.en.When;
import tech.cwvermaak.weldforge.config.tenant.TenantAccessor;
import tech.cwvermaak.weldforge.model.*;
import tech.cwvermaak.weldforge.repository.SamlServiceProviderRepository;
import tech.cwvermaak.weldforge.repository.ScimGroupRepository;
import tech.cwvermaak.weldforge.repository.TenantSigningKeyRepository;
import tech.cwvermaak.weldforge.repository.UserRepository;
import tech.cwvermaak.weldforge.service.audit.AuditService;
import tech.cwvermaak.weldforge.service.oidc.TenantSigningKeyService;
import tech.cwvermaak.weldforge.service.saml.SamlIdpService;

import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.atomic.AtomicLong;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

public class SamlIdpSteps {

    private final TestWorld world;

    private TenantAccessor tenantAccessor;
    private SamlServiceProviderRepository spRepository;
    private UserRepository userRepository;
    private ScimGroupRepository scimGroupRepository;
    private TenantSigningKeyRepository signingKeyRepository;
    private AuditService auditService;
    private SamlIdpService samlIdpService;
    private TenantSigningKeyService signingKeyService;

    private final Map<String, Tenant> tenantsBySlug = new HashMap<>();
    private final Map<Long, List<SamlServiceProvider>> spsByTenant = new HashMap<>();
    private final List<User> userStore = new ArrayList<>();
    private final Map<Long, TenantSigningKey> keysByTenant = new HashMap<>();
    private final AtomicLong idSeq = new AtomicLong(5000);

    private String lastMetadata;
    private String lastSamlResponse;
    private Throwable lastError;

    public SamlIdpSteps(TestWorld world) {
        this.world = world;
    }

    private void ensureWired() {
        if (samlIdpService != null) return;

        tenantAccessor = mock(TenantAccessor.class);
        spRepository = mock(SamlServiceProviderRepository.class);
        userRepository = mock(UserRepository.class);
        scimGroupRepository = mock(ScimGroupRepository.class);
        signingKeyRepository = mock(TenantSigningKeyRepository.class);
        auditService = mock(AuditService.class);

        // Wire signing key service with mocks
        when(signingKeyRepository.findFirstByTenantIdAndActiveTrue(anyLong())).thenAnswer(inv -> {
            Long tid = inv.getArgument(0);
            return Optional.ofNullable(keysByTenant.get(tid));
        });
        when(signingKeyRepository.save(any(TenantSigningKey.class))).thenAnswer(inv -> {
            TenantSigningKey k = inv.getArgument(0);
            if (k.getId() == null) k.setId(idSeq.getAndIncrement());
            keysByTenant.put(k.getTenant().getId(), k);
            return k;
        });
        when(signingKeyRepository.findByTenantId(anyLong())).thenAnswer(inv -> {
            Long tid = inv.getArgument(0);
            TenantSigningKey k = keysByTenant.get(tid);
            return k != null ? List.of(k) : List.of();
        });

        signingKeyService = new TenantSigningKeyService(signingKeyRepository);

        // Wire SP repository
        when(spRepository.findByTenantId(anyLong())).thenAnswer(inv -> {
            Long tid = inv.getArgument(0);
            return spsByTenant.getOrDefault(tid, List.of());
        });
        when(spRepository.findByTenantIdAndEntityId(anyLong(), anyString())).thenAnswer(inv -> {
            Long tid = inv.getArgument(0);
            String entityId = inv.getArgument(1);
            return spsByTenant.getOrDefault(tid, List.of()).stream()
                    .filter(sp -> entityId.equals(sp.getEntityId()))
                    .findFirst();
        });
        when(spRepository.findByIdAndTenantId(anyLong(), anyLong())).thenAnswer(inv -> {
            Long id = inv.getArgument(0);
            Long tid = inv.getArgument(1);
            return spsByTenant.getOrDefault(tid, List.of()).stream()
                    .filter(sp -> id.equals(sp.getId()))
                    .findFirst();
        });
        when(spRepository.save(any(SamlServiceProvider.class))).thenAnswer(inv -> {
            SamlServiceProvider sp = inv.getArgument(0);
            if (sp.getId() == null) sp.setId(idSeq.getAndIncrement());
            spsByTenant.computeIfAbsent(sp.getTenant().getId(), k -> new ArrayList<>()).add(sp);
            return sp;
        });

        when(userRepository.findByTenantIdAndEmailIgnoreCase(anyLong(), anyString())).thenAnswer(inv -> {
            Long tid = inv.getArgument(0);
            String email = inv.getArgument(1);
            return userStore.stream()
                    .filter(u -> u.getTenant().getId().equals(tid) && email.equalsIgnoreCase(u.getEmail()))
                    .findFirst();
        });

        when(scimGroupRepository.findByTenantId(anyLong())).thenReturn(List.of());

        doAnswer(inv -> {
            AuditEvent.AuditEventBuilder builder = inv.getArgument(0);
            world.auditLog.add(builder.build());
            return null;
        }).when(auditService).log(any());
        doAnswer(inv -> {
            world.auditLog.add(AuditEvent.builder()
                    .eventType(inv.getArgument(0))
                    .outcome(AuditEvent.Outcome.SUCCESS)
                    .build());
            return null;
        }).when(auditService).recordUserAction(anyString(), any(), anyString(), anyString(), any());
        doAnswer(inv -> {
            world.auditLog.add(AuditEvent.builder()
                    .eventType(inv.getArgument(0))
                    .outcome(AuditEvent.Outcome.SUCCESS)
                    .build());
            return null;
        }).when(auditService).recordAdmin(anyString(), any(), anyString(), anyString(), any());


        // Sprint 5 collaborators. The certificate service is real rather than
        // mocked: it mints an actual X.509 from the tenant's key, which is what
        // the assertions about KeyInfo and metadata need to be true of.
        var replayRepository =
                mock(tech.cwvermaak.weldforge.repository.SamlRequestReplayRepository.class);
        // Stateful, with the primary key's semantics: a second insert of the
        // same ID fails the way the real table does.
        when(replayRepository.existsById(anyString())).thenAnswer(inv ->
                spentRequestIds.contains((String) inv.getArgument(0)));
        when(replayRepository.saveAndFlush(any())).thenAnswer(inv -> {
            tech.cwvermaak.weldforge.model.SamlRequestReplay row = inv.getArgument(0);
            if (!spentRequestIds.add(row.getRequestId())) {
                throw new org.springframework.dao.DataIntegrityViolationException("duplicate key");
            }
            return row;
        });
        var signingCertificateService =
                new tech.cwvermaak.weldforge.service.saml.SamlSigningCertificateService(
                        mock(tech.cwvermaak.weldforge.repository.TenantSigningKeyRepository.class),
                        signingKeyService);

        samlIdpService = new SamlIdpService(tenantAccessor, spRepository, signingKeyService,
                userRepository, scimGroupRepository, auditService,
                signingCertificateService, publicHostProperties, replayRepository);

        // SLO collaborators: the user's login sessions are refresh-token
        // families; ending one revokes that family and nothing else.
        refreshTokenRepository = mock(tech.cwvermaak.weldforge.repository.RefreshTokenRepository.class);
        when(refreshTokenRepository.findByUserIdAndRevokedAtIsNull(anyLong())).thenAnswer(inv ->
                liveSessions.values().stream()
                        .filter(f -> !revokedFamilies.contains(f))
                        .map(f -> RefreshToken.builder().familyId(f).build())
                        .toList());
        familyRevoker = mock(tech.cwvermaak.weldforge.service.security.RefreshTokenFamilyRevoker.class);
        when(familyRevoker.revoke(any(), anyString())).thenAnswer(inv -> {
            revokedFamilies.add(inv.getArgument(0));
            return 1;
        });
        authService = mock(tech.cwvermaak.weldforge.service.AuthService.class);
        sloService = new tech.cwvermaak.weldforge.service.saml.SamlSloService(spRepository, auditService,
                samlIdpService, refreshTokenRepository, familyRevoker, authService);
    }

    private final tech.cwvermaak.weldforge.config.tenant.PublicHostProperties publicHostProperties =
            new tech.cwvermaak.weldforge.config.tenant.PublicHostProperties();
    private final Set<String> spentRequestIds = new HashSet<>();
    private final Map<String, UUID> liveSessions = new LinkedHashMap<>();
    private final Set<UUID> revokedFamilies = new HashSet<>();
    private tech.cwvermaak.weldforge.repository.RefreshTokenRepository refreshTokenRepository;
    private tech.cwvermaak.weldforge.service.security.RefreshTokenFamilyRevoker familyRevoker;
    private tech.cwvermaak.weldforge.service.AuthService authService;
    private tech.cwvermaak.weldforge.service.saml.SamlSloService sloService;

    private Tenant createTenant(String slug) {
        Tenant t = Tenant.builder().id(idSeq.getAndIncrement()).slug(slug).name(slug).build();
        tenantsBySlug.put(slug, t);
        // Generate a signing key for this tenant
        signingKeyService.getOrCreateActive(t);
        return t;
    }

    private SamlServiceProvider registerSp(Tenant tenant, String entityId) {
        SamlServiceProvider sp = SamlServiceProvider.builder()
                .id(idSeq.getAndIncrement())
                .tenant(tenant)
                .entityId(entityId)
                .name("Test SP")
                .acsUrl(entityId + "/acs")
                .nameIdFormat("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress")
                .enabled(true)
                .createdAt(LocalDateTime.now())
                .updatedAt(LocalDateTime.now())
                .build();
        spsByTenant.computeIfAbsent(tenant.getId(), k -> new ArrayList<>()).add(sp);
        return sp;
    }

    @Given("tenant {string} is configured for SAML IdP")
    public void tenantConfigured(String slug) {
        ensureWired();
        Tenant t = createTenant(slug);
        when(tenantAccessor.requireTenant()).thenReturn(t);
        when(tenantAccessor.requireTenantId()).thenReturn(t.getId());
    }

    @Given("a SAML service provider {string} is registered for tenant {string}")
    public void spRegistered(String entityId, String slug) {
        Tenant t = tenantsBySlug.get(slug);
        registerSp(t, entityId);
    }

    @Given("user {string} exists for SAML IdP in tenant {string}")
    public void userExists(String email, String slug) {
        Tenant t = tenantsBySlug.get(slug);
        User u = User.builder()
                .id(idSeq.getAndIncrement())
                .tenant(t)
                .email(email)
                .username(email)
                .active(true)
                .provider(AuthProvider.LOCAL)
                .providerId("local")
                .build();
        userStore.add(u);
    }

    @Given("tenant {string} is configured for SAML IdP with SP {string}")
    public void otherTenantWithSp(String slug, String entityId) {
        ensureWired();
        Tenant t = createTenant(slug);
        registerSp(t, entityId);
    }

    @When("I fetch the IdP metadata for tenant {string}")
    public void fetchMetadata(String slug) {
        Tenant t = tenantsBySlug.get(slug);
        lastMetadata = samlIdpService.generateMetadata(t, "https://sso.test");
    }

    @Then("the metadata entity ID contains {string}")
    public void metadataEntityIdContains(String expected) {
        // The canonical entityID, whatever host the metadata was fetched from:
        // it has to equal the Issuer an opted-in SP receives (CONF-5.4).
        assertThat(lastMetadata).contains("entityID=\""
                + publicHostProperties.originForTenant(null) + "/t/" + expected);
    }

    @Then("the metadata includes an SSO endpoint")
    public void metadataIncludesSso() {
        assertThat(lastMetadata).contains("SingleSignOnService");
        assertThat(lastMetadata).contains("HTTP-POST");
    }

    @Then("the metadata includes a signing key")
    public void metadataIncludesKey() {
        assertThat(lastMetadata).contains("KeyDescriptor");
        assertThat(lastMetadata).contains("X509Certificate");
    }

    @When("a SAML Response is built for {string} to SP {string}")
    public void buildResponse(String email, String spEntityId) {
        Tenant t = tenantsBySlug.get("acme");
        User user = userStore.stream()
                .filter(u -> email.equalsIgnoreCase(u.getEmail()) && u.getTenant().getId().equals(t.getId()))
                .findFirst().orElseThrow();
        SamlServiceProvider sp = spsByTenant.get(t.getId()).stream()
                .filter(s -> spEntityId.equals(s.getEntityId()))
                .findFirst().orElseThrow();

        lastSamlResponse = samlIdpService.buildSamlResponse(t, user, sp, "_req123");
    }

    @Then("the SAML response is base64-encoded")
    public void responseIsBase64() {
        assertThat(lastSamlResponse).isNotNull();
        // Should be valid base64
        byte[] decoded = Base64.getDecoder().decode(lastSamlResponse);
        assertThat(decoded).isNotEmpty();
    }

    @Then("the decoded response contains assertion subject {string}")
    public void responseContainsSubject(String expected) {
        String xml = new String(Base64.getDecoder().decode(lastSamlResponse), StandardCharsets.UTF_8);
        assertThat(xml).contains(expected);
    }

    @Then("the decoded response contains audience {string}")
    public void responseContainsAudience(String expected) {
        String xml = new String(Base64.getDecoder().decode(lastSamlResponse), StandardCharsets.UTF_8);
        assertThat(xml).contains(expected);
    }

    @Then("a {string} audit event is recorded for SAML IdP")
    public void auditRecorded(String type) {
        assertThat(world.auditLog)
                .extracting(AuditEvent::getEventType)
                .contains(type);
    }

    @When("an AuthnRequest from {string} is validated for tenant {string}")
    public void validateAuthnRequest(String issuer, String slug) {
        Tenant t = tenantsBySlug.get(slug);
        lastError = null;
        try {
            samlIdpService.validateAuthnRequest(t, issuer);
        } catch (Exception e) {
            lastError = e;
        }
    }

    @Then("the SAML IdP request is rejected")
    public void requestRejected() {
        assertThat(lastError).isNotNull();
        assertThat(lastError).isInstanceOf(IllegalArgumentException.class);
    }

    // ---- inbound XML hardening (B-SAML-1) ----------------------------

    private tech.cwvermaak.weldforge.service.saml.SamlInboundMessageParser.ParsedMessage parsedMessage;

    @When("a raw SAML AuthnRequest from {string} is parsed")
    public void parseRawAuthnRequest(String issuer) {
        String xml = "<samlp:AuthnRequest xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" "
                + "xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"_req1\" Version=\"2.0\">"
                + "<saml:Issuer>" + issuer + "</saml:Issuer></samlp:AuthnRequest>";
        lastError = null;
        parsedMessage = null;
        try {
            parsedMessage = tech.cwvermaak.weldforge.service.saml.SamlInboundMessageParser.parse(xml);
        } catch (Exception e) {
            lastError = e;
        }
    }

    @Then("the parsed SAML issuer is {string}")
    public void parsedIssuerIs(String expected) {
        assertThat(parsedMessage).isNotNull();
        assertThat(parsedMessage.issuer()).isEqualTo(expected);
    }

    @When("a SAML AuthnRequest containing a DOCTYPE is parsed")
    public void parseDoctype() {
        String xxe = "<?xml version=\"1.0\"?>"
                + "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>"
                + "<samlp:AuthnRequest xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" "
                + "xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"_x\">"
                + "<saml:Issuer>&xxe;</saml:Issuer></samlp:AuthnRequest>";
        lastError = null;
        try {
            tech.cwvermaak.weldforge.service.saml.SamlInboundMessageParser.parse(xxe);
        } catch (Exception e) {
            lastError = e;
        }
    }

    @Then("the SAML message is rejected as unsafe")
    public void messageRejectedUnsafe() {
        assertThat(lastError).isInstanceOf(
                tech.cwvermaak.weldforge.service.saml.SamlMessageException.class);
    }

    // ---- AuthnRequest signature verification (B-SAML-1 part a) --------

    private java.security.KeyPair spKeyPair;
    private tech.cwvermaak.weldforge.model.SamlServiceProvider signingSp;

    @io.cucumber.java.en.Given("an SP {string} that requires signed AuthnRequests")
    public void spRequiresSigning(String entityId) throws Exception {
        spKeyPair = tech.cwvermaak.weldforge.service.saml.SamlTestCrypto.generateKeyPair();
        String certPem = tech.cwvermaak.weldforge.service.saml.SamlTestCrypto.selfSignedCertPem(spKeyPair);
        signingSp = tech.cwvermaak.weldforge.model.SamlServiceProvider.builder()
                .entityId(entityId).acsUrl("https://sp/acs").spCertificate(certPem)
                .wantAuthnRequestSigned(true).enabled(true).build();
    }

    @io.cucumber.java.en.Given("an SP {string} that does not require signed AuthnRequests")
    public void spNoSigning(String entityId) {
        spKeyPair = null;
        signingSp = tech.cwvermaak.weldforge.model.SamlServiceProvider.builder()
                .entityId(entityId).acsUrl("https://sp/acs")
                .wantAuthnRequestSigned(false).enabled(true).build();
    }

    @When("a validly-signed AuthnRequest from that SP is verified")
    public void verifySignedRequest() {
        lastError = null;
        try {
            String signed = tech.cwvermaak.weldforge.service.saml.SamlTestCrypto.sign(
                    tech.cwvermaak.weldforge.service.saml.SamlTestCrypto.authnRequest(
                            signingSp.getEntityId(), "_sig1"), spKeyPair);
            samlIdpService.verifyAuthnRequestSignature(signingSp, signed);
        } catch (Exception e) {
            lastError = e;
        }
    }

    @When("an unsigned AuthnRequest from that SP is verified")
    public void verifyUnsignedRequest() {
        lastError = null;
        try {
            String unsigned = tech.cwvermaak.weldforge.service.saml.SamlTestCrypto.authnRequest(
                    signingSp.getEntityId(), "_uns1");
            samlIdpService.verifyAuthnRequestSignature(signingSp, unsigned);
        } catch (Exception e) {
            lastError = e;
        }
    }

    @Then("the SAML signature check passes")
    public void signatureCheckPasses() {
        assertThat(lastError).isNull();
    }

    @Then("the SAML signature check fails")
    public void signatureCheckFails() {
        assertThat(lastError).isInstanceOf(
                tech.cwvermaak.weldforge.service.saml.SamlMessageException.class);
    }

    @When("an SP {string} is registered requiring signed AuthnRequests")
    public void registerSpRequiringSignature(String entityId) {
        var dto = tech.cwvermaak.weldforge.model.dto.SamlServiceProviderDto.builder()
                .entityId(entityId).acsUrl(entityId + "/acs")
                .wantAuthnRequestSigned(true).build();
        samlIdpService.create(dto);
    }

    @Then("the registered SP {string} requires signed AuthnRequests")
    public void registeredSpRequiresSignature(String entityId) {
        var dto = samlIdpService.list().stream()
                .filter(d -> entityId.equals(d.getEntityId()))
                .findFirst().orElseThrow();
        assertThat(dto.getWantAuthnRequestSigned()).isTrue();
    }

    // ---- Sprint 5: assertion fidelity ---------------------------------

    private SamlServiceProvider spByEntityId(String spEntityId) {
        Tenant t = tenantsBySlug.get("acme");
        return spsByTenant.get(t.getId()).stream()
                .filter(sp -> spEntityId.equals(sp.getEntityId()))
                .findFirst().orElseThrow();
    }

    private String decodedResponse() {
        return new String(Base64.getDecoder().decode(lastSamlResponse), StandardCharsets.UTF_8);
    }

    @Given("SP {string} pins its authentication context to the password class")
    public void spPinsContext(String spEntityId) {
        spByEntityId(spEntityId).setAuthnContextOverride(
                tech.cwvermaak.weldforge.service.saml.SamlIdpService.AUTHN_CTX_PASSWORD_PROTECTED);
    }

    @Given("SP {string} opts in to the entityID issuer")
    public void spOptsInToEntityIdIssuer(String spEntityId) {
        spByEntityId(spEntityId).setUseEntityIdAsIssuer(true);
    }

    @When("a SAML Response is built for {string} to SP {string} with factors {string}")
    public void buildResponseWithFactors(String email, String spEntityId, String factors) {
        Tenant t = tenantsBySlug.get("acme");
        User user = userStore.stream()
                .filter(u -> email.equalsIgnoreCase(u.getEmail()) && u.getTenant().getId().equals(t.getId()))
                .findFirst().orElseThrow();
        lastSamlResponse = samlIdpService.buildSamlResponse(
                t, user, spByEntityId(spEntityId), "_req123",
                java.util.Arrays.stream(factors.split("\s+")).toList(), null);
    }

    @Then("the assertion's authentication context is the two-factor class")
    public void contextIsTwoFactor() {
        assertThat(decodedResponse())
                .contains(tech.cwvermaak.weldforge.service.saml.SamlIdpService.AUTHN_CTX_MOBILE_TWO_FACTOR);
    }

    @Then("the assertion's authentication context is the password class")
    public void contextIsPassword() {
        assertThat(decodedResponse())
                .contains(tech.cwvermaak.weldforge.service.saml.SamlIdpService.AUTHN_CTX_PASSWORD_PROTECTED);
    }

    @Then("the assertion carries a session index")
    public void assertionCarriesSessionIndex() {
        assertThat(decodedResponse()).containsPattern("SessionIndex=\"[^\"]+\"");
    }

    @Then("the signature KeyInfo contains an X509 certificate")
    public void keyInfoHasCertificate() {
        assertThat(decodedResponse()).contains("X509Certificate");
    }

    @Then("the signature KeyInfo contains no bare KeyValue")
    public void keyInfoHasNoKeyValue() {
        // A verifier resolving the key from KeyInfo expects X509Data; a raw
        // modulus and exponent leaves it nothing to match against the
        // certificate published in metadata.
        assertThat(decodedResponse()).doesNotContain("KeyValue");
    }

    @Then("the assertion issuer is {string}")
    public void assertionIssuerIs(String expected) {
        assertThat(decodedResponse()).contains("<saml:Issuer>" + expected + "</saml:Issuer>");
    }

    @Then("the assertion issuer is the tenant's metadata entityID")
    public void assertionIssuerIsEntityId() {
        String entityId = samlIdpService.metadataEntityId(tenantsBySlug.get("acme"));
        assertThat(decodedResponse()).contains("<saml:Issuer>" + entityId + "</saml:Issuer>");
    }

    // ---- Sprint 5 follow-up: replay, freshness, signing intent, logout ----

    private static final String ACME_SP = "https://app.acme.test/saml";

    private void receiveAuthnRequest(String requestId, java.time.Instant issueInstant) {
        Tenant t = tenantsBySlug.get("acme");
        lastError = null;
        try {
            samlIdpService.rejectReplayedRequest(t, spByEntityId(ACME_SP), requestId, issueInstant);
        } catch (Exception e) {
            lastError = e;
        }
    }

    @Given("an AuthnRequest with ID {string} was processed")
    public void authnRequestProcessed(String requestId) {
        receiveAuthnRequest(requestId, java.time.Instant.now());
        assertThat(lastError).as("the first use of a request ID is accepted").isNull();
    }

    @When("the same AuthnRequest ID {string} arrives again")
    public void authnRequestArrivesAgain(String requestId) {
        receiveAuthnRequest(requestId, java.time.Instant.now());
    }

    @When("an AuthnRequest with ID {string} issued {int} minutes ago arrives")
    public void authnRequestIssuedAgo(String requestId, int minutes) {
        receiveAuthnRequest(requestId, java.time.Instant.now().minus(java.time.Duration.ofMinutes(minutes)));
    }

    @When("an AuthnRequest with ID {string} issued {int} minutes in the future arrives")
    public void authnRequestIssuedAhead(String requestId, int minutes) {
        receiveAuthnRequest(requestId, java.time.Instant.now().plus(java.time.Duration.ofMinutes(minutes)));
    }

    @Then("the AuthnRequest is refused")
    public void authnRequestRefused() {
        assertThat(lastError).isInstanceOf(tech.cwvermaak.weldforge.service.saml.SamlMessageException.class);
    }

    @Then("the AuthnRequest is accepted")
    public void authnRequestAccepted() {
        assertThat(lastError).isNull();
    }

    @Then("a {string} audit event is recorded with outcome DENIED")
    public void auditRecordedDenied(String type) {
        assertThat(world.auditLog)
                .filteredOn(e -> type.equals(e.getEventType()))
                .extracting(AuditEvent::getOutcome)
                .contains(AuditEvent.Outcome.DENIED);
    }

    @Given("tenant {string} requires signed AuthnRequests by default")
    public void tenantRequiresSignedRequests(String slug) {
        tenantsBySlug.get(slug).setSamlWantAuthnRequestsSigned(true);
    }

    @Then("its IdP metadata advertises WantAuthnRequestsSigned={string}")
    public void metadataAdvertisesSigning(String value) {
        assertThat(lastMetadata).contains("WantAuthnRequestsSigned=\"" + value + "\"");
    }

    @Given("alice has login sessions {string} and {string}")
    public void aliceHasSessions(String a, String b) {
        liveSessions.put(a, UUID.randomUUID());
        liveSessions.put(b, UUID.randomUUID());
    }

    private User alice() {
        Tenant t = tenantsBySlug.get("acme");
        return userStore.stream()
                .filter(u -> "alice@acme.test".equalsIgnoreCase(u.getEmail())
                        && u.getTenant().getId().equals(t.getId()))
                .findFirst().orElseThrow();
    }

    private final List<String> sessionIndexesSeen = new ArrayList<>();

    @When("assertions are built for alice's session {string} to SP {string} twice")
    public void assertionsForSessionTwice(String session, String spEntityId) {
        String sid = liveSessions.get(session).toString();
        SamlServiceProvider sp = spByEntityId(spEntityId);
        for (int i = 0; i < 2; i++) {
            lastSamlResponse = samlIdpService.buildSamlResponse(tenantsBySlug.get("acme"), alice(), sp,
                    "_req" + i, List.of("pwd"), SamlIdpService.sessionIndexFor(sid, sp));
            java.util.regex.Matcher m = java.util.regex.Pattern
                    .compile("SessionIndex=\"([^\"]+)\"").matcher(decodedResponse());
            assertThat(m.find()).isTrue();
            sessionIndexesSeen.add(m.group(1));
        }
    }

    @Then("both assertions carry the same session index")
    public void sameSessionIndex() {
        assertThat(sessionIndexesSeen).hasSize(2);
        assertThat(sessionIndexesSeen.get(0)).isEqualTo(sessionIndexesSeen.get(1));
    }

    @Then("another SP is given a different session index for session {string}")
    public void differentSpDifferentIndex(String session) {
        SamlServiceProvider other = SamlServiceProvider.builder().entityId("https://other.acme.test/saml").build();
        assertThat(SamlIdpService.sessionIndexFor(liveSessions.get(session).toString(), other))
                .isNotEqualTo(sessionIndexesSeen.get(0));
    }

    @When("SP {string} sends a LogoutRequest naming alice's session {string}")
    public void logoutNamingSession(String spEntityId, String session) {
        SamlServiceProvider sp = spByEntityId(spEntityId);
        sloService.terminateSessions(tenantsBySlug.get("acme"), sp, alice(),
                List.of(SamlIdpService.sessionIndexFor(liveSessions.get(session).toString(), sp)), null);
    }

    @When("SP {string} sends a LogoutRequest naming no session")
    public void logoutNamingNoSession(String spEntityId) {
        sloService.terminateSessions(tenantsBySlug.get("acme"), spByEntityId(spEntityId), alice(),
                List.of(), null);
    }

    @Then("only alice's session {string} is terminated")
    public void onlySessionTerminated(String session) {
        assertThat(revokedFamilies).containsExactly(liveSessions.get(session));
        verify(authService, never()).logoutAll(any());
    }

    @Then("all of alice's sessions are terminated")
    public void allSessionsTerminated() {
        verify(authService).logoutAll(alice());
    }

    @Then("a {string} audit event is recorded for the logout")
    public void logoutAudited(String type) {
        auditRecorded(type);
    }

    @When("an IdP-initiated LogoutRequest is built for alice to SP {string}")
    public void idpLogoutRequest(String spEntityId) {
        lastSamlResponse = sloService.buildLogoutRequest(tenantsBySlug.get("acme"), alice(),
                spByEntityId(spEntityId), tech.cwvermaak.weldforge.service.saml.SamlSloService.Binding.POST);
    }

    @Then("the LogoutRequest issuer is the tenant's metadata entityID")
    public void logoutRequestIssuerIsEntityId() {
        assertionIssuerIsEntityId();
    }
}
