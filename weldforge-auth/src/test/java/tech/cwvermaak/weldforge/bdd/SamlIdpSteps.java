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

        samlIdpService = new SamlIdpService(tenantAccessor, spRepository, signingKeyService,
                userRepository, scimGroupRepository, auditService);
    }

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
        assertThat(lastMetadata).contains("entityID=\"https://sso.test/t/" + expected);
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
}
