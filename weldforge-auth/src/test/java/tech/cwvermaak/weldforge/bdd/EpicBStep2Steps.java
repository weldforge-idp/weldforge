package tech.cwvermaak.weldforge.bdd;

import io.cucumber.java.en.Given;
import io.cucumber.java.en.Then;
import io.cucumber.java.en.When;
import tech.cwvermaak.weldforge.config.tenant.TenantAccessor;
import tech.cwvermaak.weldforge.model.AuthProvider;
import tech.cwvermaak.weldforge.model.SamlServiceProvider;
import tech.cwvermaak.weldforge.model.Tenant;
import tech.cwvermaak.weldforge.model.TenantSigningKey;
import tech.cwvermaak.weldforge.model.User;
import tech.cwvermaak.weldforge.model.dto.SamlProviderDto;
import tech.cwvermaak.weldforge.repository.SamlServiceProviderRepository;
import tech.cwvermaak.weldforge.repository.ScimGroupRepository;
import tech.cwvermaak.weldforge.repository.TenantSigningKeyRepository;
import tech.cwvermaak.weldforge.repository.UserRepository;
import tech.cwvermaak.weldforge.service.audit.AuditService;
import tech.cwvermaak.weldforge.service.oidc.TenantSigningKeyService;
import tech.cwvermaak.weldforge.service.saml.SamlIdpService;
import tech.cwvermaak.weldforge.service.saml.SamlMetadataParser;
import tech.cwvermaak.weldforge.service.saml.SamlSloService;

import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.atomic.AtomicLong;
import java.util.zip.Inflater;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.*;

public class EpicBStep2Steps {

    private final TestWorld world;
    private final AtomicLong ids = new AtomicLong(17000);

    // Mocks
    private TenantAccessor tenantAccessor;
    private SamlServiceProviderRepository spRepository;
    private TenantSigningKeyRepository signingKeyRepo;
    private UserRepository userRepository;
    private ScimGroupRepository scimGroupRepository;
    private AuditService auditService;

    // Services under test
    private SamlMetadataParser metadataParser;
    private SamlIdpService idpService;
    private SamlSloService sloService;
    private TenantSigningKeyService signingKeyService;

    // State
    private final Map<String, Tenant> tenantsBySlug = new HashMap<>();
    private final Map<String, User> users = new HashMap<>();
    private final List<SamlServiceProvider> spStore = new ArrayList<>();
    private final Map<Long, TenantSigningKey> keysByTenant = new HashMap<>();

    private SamlMetadataParser.ParsedMetadata lastParsed;
    private Throwable lastError;
    private String lastNameIdA;
    private String lastNameIdB;
    private List<SamlSloService.SloPayload> lastPayloads;
    private String lastAssertionXml;

    public EpicBStep2Steps(TestWorld world) {
        this.world = world;
    }

    private void ensureWired() {
        if (metadataParser != null) return;

        metadataParser = new SamlMetadataParser();

        tenantAccessor = mock(TenantAccessor.class);
        spRepository = mock(SamlServiceProviderRepository.class);
        userRepository = mock(UserRepository.class);
        scimGroupRepository = mock(ScimGroupRepository.class);
        signingKeyRepo = mock(TenantSigningKeyRepository.class);
        auditService = mock(AuditService.class);

        // Signing keys per tenant, generated on demand
        when(signingKeyRepo.findFirstByTenantIdAndActiveTrue(anyLong())).thenAnswer(inv ->
                Optional.ofNullable(keysByTenant.get((Long) inv.getArgument(0))));
        when(signingKeyRepo.save(any(TenantSigningKey.class))).thenAnswer(inv -> {
            TenantSigningKey k = inv.getArgument(0);
            if (k.getId() == null) k.setId(ids.getAndIncrement());
            keysByTenant.put(k.getTenant().getId(), k);
            return k;
        });
        when(signingKeyRepo.findByTenantId(anyLong())).thenAnswer(inv -> {
            TenantSigningKey k = keysByTenant.get((Long) inv.getArgument(0));
            return k != null ? List.of(k) : List.of();
        });
        signingKeyService = new TenantSigningKeyService(signingKeyRepo);

        // SP repository — filtered by tenant + entityId / enabled
        when(spRepository.findByTenantIdAndEntityId(anyLong(), any())).thenAnswer(inv -> {
            Long tid = inv.getArgument(0);
            String entityId = inv.getArgument(1);
            return spStore.stream()
                    .filter(sp -> sp.getTenant().getId().equals(tid) && entityId.equals(sp.getEntityId()))
                    .findFirst();
        });
        when(spRepository.findByTenantIdAndEnabledTrue(anyLong())).thenAnswer(inv -> {
            Long tid = inv.getArgument(0);
            return spStore.stream()
                    .filter(sp -> sp.getTenant().getId().equals(tid) && Boolean.TRUE.equals(sp.getEnabled()))
                    .toList();
        });
        when(spRepository.findByTenantId(anyLong())).thenAnswer(inv -> {
            Long tid = inv.getArgument(0);
            return spStore.stream().filter(sp -> sp.getTenant().getId().equals(tid)).toList();
        });

        when(scimGroupRepository.findByTenantId(anyLong())).thenReturn(List.of());

        idpService = new SamlIdpService(tenantAccessor, spRepository, signingKeyService,
                userRepository, scimGroupRepository, auditService);
        sloService = new SamlSloService(spRepository, auditService);
    }

    private Tenant tenant(String slug) {
        return tenantsBySlug.computeIfAbsent(slug, s ->
                Tenant.builder().id(ids.getAndIncrement()).slug(s).name(s).build());
    }

    // ---- Background ------------------------------------------------

    @Given("tenant {string} exists for SAML completeness tests")
    public void tenantExists(String slug) {
        ensureWired();
        tenant(slug);
    }

    @Given("user {string} exists for SAML completeness tests")
    public void userExists(String email) {
        Tenant t = tenantsBySlug.values().iterator().next();
        User u = User.builder()
                .id(ids.getAndIncrement())
                .tenant(t)
                .email(email)
                .username(email)
                .name("Alice Acme")
                .active(true)
                .provider(AuthProvider.LOCAL)
                .providerId("local")
                .build();
        users.put(email.toLowerCase(), u);
    }

    // ---- SAM-05: metadata import -----------------------------------

    @When("the admin imports SP metadata XML with entityID {string}")
    public void importSpMetadata(String entityId) {
        String xml = """
            <md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
                                 xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
                                 entityID="%s">
              <md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
                <md:KeyDescriptor use="signing">
                  <ds:KeyInfo>
                    <ds:X509Data>
                      <ds:X509Certificate>MIICdummycertbase64dummycertbase64dummycertbase64dummycertbase64dummycertbase64==</ds:X509Certificate>
                    </ds:X509Data>
                  </ds:KeyInfo>
                </md:KeyDescriptor>
                <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>
                <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                                             Location="%s/acs" index="0"/>
                <md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                                        Location="%s/slo"/>
              </md:SPSSODescriptor>
            </md:EntityDescriptor>
            """.formatted(entityId, entityId, entityId);
        lastError = null;
        try {
            lastParsed = metadataParser.parseXml(xml);
        } catch (Exception e) {
            lastError = e;
        }
    }

    @When("the admin imports IdP metadata XML with entityID {string}")
    public void importIdpMetadata(String entityId) {
        String xml = """
            <md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
                                 xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
                                 entityID="%s">
              <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
                <md:KeyDescriptor use="signing">
                  <ds:KeyInfo>
                    <ds:X509Data>
                      <ds:X509Certificate>MIICdummycertbase64dummycertbase64dummycertbase64dummycertbase64dummycertbase64==</ds:X509Certificate>
                    </ds:X509Data>
                  </ds:KeyInfo>
                </md:KeyDescriptor>
                <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                                        Location="%s/sso"/>
                <md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                                        Location="%s/slo"/>
              </md:IDPSSODescriptor>
            </md:EntityDescriptor>
            """.formatted(entityId, entityId, entityId);
        lastError = null;
        try {
            lastParsed = metadataParser.parseXml(xml);
        } catch (Exception e) {
            lastError = e;
        }
    }

    @When("the admin imports SP metadata XML containing a DOCTYPE declaration")
    public void importSpMetadataWithDoctype() {
        String xml = "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>"
                + "<md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" entityID=\"bad\">"
                + "</md:EntityDescriptor>";
        lastError = null;
        try {
            lastParsed = metadataParser.parseXml(xml);
        } catch (Exception e) {
            lastError = e;
        }
    }

    @Then("the parsed SP dto has entityId {string}")
    public void parsedSpHasEntityId(String expected) {
        assertThat(lastParsed).isNotNull();
        assertThat(lastParsed.kind()).isEqualTo(SamlMetadataParser.ParsedKind.SP);
        assertThat(lastParsed.spDto().getEntityId()).isEqualTo(expected);
    }

    @Then("the parsed SP dto has an ACS url")
    public void parsedSpHasAcsUrl() {
        assertThat(lastParsed.spDto().getAcsUrl()).isNotBlank();
    }

    @Then("the parsed SP dto has a signing certificate in PEM format")
    public void parsedSpHasPemCert() {
        String cert = lastParsed.spDto().getSpCertificate();
        assertThat(cert).isNotNull();
        assertThat(cert).startsWith("-----BEGIN CERTIFICATE-----");
        assertThat(cert).endsWith("-----END CERTIFICATE-----");
    }

    @Then("the parsed IdP dto has entityId {string}")
    public void parsedIdpHasEntityId(String expected) {
        assertThat(lastParsed).isNotNull();
        assertThat(lastParsed.kind()).isEqualTo(SamlMetadataParser.ParsedKind.IDP);
        SamlProviderDto dto = lastParsed.idpDto();
        assertThat(dto.getIdpEntityId()).isEqualTo(expected);
    }

    @Then("the parsed IdP dto has an SSO url")
    public void parsedIdpHasSsoUrl() {
        assertThat(lastParsed.idpDto().getIdpSsoUrl()).isNotBlank();
    }

    @Then("the metadata parse is rejected")
    public void metadataRejected() {
        assertThat(lastError).isNotNull();
        assertThat(lastError).isInstanceOf(IllegalArgumentException.class);
    }

    // ---- SAM-07: NameID formats ------------------------------------

    @When("a NameID is resolved for alice with format {string}")
    public void resolveNameId(String format) {
        User alice = users.get("alice@acme.test");
        lastNameIdA = SamlIdpService.resolveNameId(alice, format);
    }

    @Then("the resolved NameID is {string}")
    public void resolvedNameIdIs(String expected) {
        assertThat(lastNameIdA).isEqualTo(expected);
    }

    @Then("the resolved NameID is the user id")
    public void resolvedNameIdIsUserId() {
        User alice = users.get("alice@acme.test");
        assertThat(lastNameIdA).isEqualTo(String.valueOf(alice.getId()));
    }

    @When("two NameIDs are resolved with format {string}")
    public void resolveTwoNameIds(String format) {
        User alice = users.get("alice@acme.test");
        lastNameIdA = SamlIdpService.resolveNameId(alice, format);
        lastNameIdB = SamlIdpService.resolveNameId(alice, format);
    }

    @Then("the two resolved NameIDs are different")
    public void twoNameIdsDiffer() {
        assertThat(lastNameIdA).isNotEqualTo(lastNameIdB);
    }

    // ---- SAM-06: SLO bindings --------------------------------------

    @Given("an SP {string} is registered for tenant {string} with SLO URL")
    public void registerSpWithSlo(String entityId, String slug) {
        Tenant t = tenantsBySlug.get(slug);
        SamlServiceProvider sp = SamlServiceProvider.builder()
                .id(ids.getAndIncrement())
                .tenant(t)
                .entityId(entityId)
                .name("Acme App")
                .acsUrl(entityId + "/acs")
                .sloUrl(entityId + "/slo")
                .nameIdFormat(SamlIdpService.NAMEID_EMAIL)
                .enabled(true)
                .createdAt(LocalDateTime.now())
                .updatedAt(LocalDateTime.now())
                .build();
        spStore.add(sp);
    }

    @When("alice initiates SLO with POST binding")
    public void initiateSloPost() {
        User alice = users.get("alice@acme.test");
        Tenant t = alice.getTenant();
        lastPayloads = sloService.initiateLogout(t, alice, SamlSloService.Binding.POST);
    }

    @When("alice initiates SLO with REDIRECT binding")
    public void initiateSloRedirect() {
        User alice = users.get("alice@acme.test");
        Tenant t = alice.getTenant();
        lastPayloads = sloService.initiateLogout(t, alice, SamlSloService.Binding.REDIRECT);
    }

    @Then("the logout payload is base64 raw xml")
    public void payloadIsBase64Raw() {
        assertThat(lastPayloads).hasSize(1);
        String encoded = lastPayloads.get(0).logoutRequest();
        byte[] decoded = Base64.getDecoder().decode(encoded);
        String xml = new String(decoded, StandardCharsets.UTF_8);
        assertThat(xml).contains("LogoutRequest");
    }

    @Then("the logout payload contains {string}")
    public void payloadContains(String expected) {
        String encoded = lastPayloads.get(0).logoutRequest();
        byte[] decoded = Base64.getDecoder().decode(encoded);
        String xml = new String(decoded, StandardCharsets.UTF_8);
        assertThat(xml).contains(expected);
    }

    @Then("the logout payload is deflate-compressed base64")
    public void payloadIsDeflateBase64() throws Exception {
        assertThat(lastPayloads).hasSize(1);
        String encoded = lastPayloads.get(0).logoutRequest();
        byte[] deflated = Base64.getDecoder().decode(encoded);

        // Raw DEFLATE (no zlib wrapper) — use Inflater with nowrap=true.
        Inflater inf = new Inflater(true);
        inf.setInput(deflated);
        byte[] buf = new byte[4096];
        int n = inf.inflate(buf);
        inf.end();

        String xml = new String(buf, 0, n, StandardCharsets.UTF_8);
        assertThat(xml).contains("LogoutRequest");
    }

    // ---- SAM-08: attribute release ---------------------------------

    @Given("an SP {string} is registered for tenant {string} with release policy email name")
    public void registerSpWithReleasePolicy(String entityId, String slug) {
        Tenant t = tenantsBySlug.get(slug);
        Map<String, Object> mappings = new HashMap<>();
        mappings.put("_release", List.of("email", "name"));
        SamlServiceProvider sp = SamlServiceProvider.builder()
                .id(ids.getAndIncrement())
                .tenant(t)
                .entityId(entityId)
                .name("Acme App")
                .acsUrl(entityId + "/acs")
                .nameIdFormat(SamlIdpService.NAMEID_EMAIL)
                .attributeMappings(mappings)
                .enabled(true)
                .createdAt(LocalDateTime.now())
                .updatedAt(LocalDateTime.now())
                .build();
        spStore.add(sp);
    }

    @Given("an SP {string} is registered for tenant {string} with no release policy")
    public void registerSpNoReleasePolicy(String entityId, String slug) {
        Tenant t = tenantsBySlug.get(slug);
        SamlServiceProvider sp = SamlServiceProvider.builder()
                .id(ids.getAndIncrement())
                .tenant(t)
                .entityId(entityId)
                .name("Acme App")
                .acsUrl(entityId + "/acs")
                .nameIdFormat(SamlIdpService.NAMEID_EMAIL)
                .enabled(true)
                .createdAt(LocalDateTime.now())
                .updatedAt(LocalDateTime.now())
                .build();
        spStore.add(sp);
    }

    @When("alice receives a SAML assertion for the SP")
    public void aliceReceivesAssertion() {
        User alice = users.get("alice@acme.test");
        Tenant t = alice.getTenant();
        SamlServiceProvider sp = spStore.stream()
                .filter(s -> s.getTenant().getId().equals(t.getId()))
                .findFirst().orElseThrow();
        String b64 = idpService.buildSamlResponse(t, alice, sp, "_req-" + UUID.randomUUID());
        lastAssertionXml = new String(Base64.getDecoder().decode(b64), StandardCharsets.UTF_8);
    }

    @Then("the assertion contains attribute {string}")
    public void assertionContainsAttribute(String name) {
        assertThat(lastAssertionXml).contains("Name=\"" + name + "\"");
    }

    @Then("the assertion does not contain attribute {string}")
    public void assertionDoesNotContainAttribute(String name) {
        assertThat(lastAssertionXml).doesNotContain("Name=\"" + name + "\"");
    }
}
