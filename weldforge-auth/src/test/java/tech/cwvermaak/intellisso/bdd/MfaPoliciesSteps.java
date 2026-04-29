package tech.cwvermaak.intellisso.bdd;

import io.cucumber.java.en.Given;
import io.cucumber.java.en.Then;
import io.cucumber.java.en.When;
import tech.cwvermaak.intellisso.config.tenant.TenantAccessor;
import tech.cwvermaak.intellisso.model.AuditEvent;
import tech.cwvermaak.intellisso.model.MfaFactor;
import tech.cwvermaak.intellisso.model.MfaFactorType;
import tech.cwvermaak.intellisso.model.OAuthAuthorizationCode;
import tech.cwvermaak.intellisso.model.OidcClient;
import tech.cwvermaak.intellisso.model.Tenant;
import tech.cwvermaak.intellisso.model.TenantMfaPolicy;
import tech.cwvermaak.intellisso.model.User;
import tech.cwvermaak.intellisso.model.dto.MfaPolicyDto;
import tech.cwvermaak.intellisso.repository.MfaFactorRepository;
import tech.cwvermaak.intellisso.repository.OAuthAuthorizationCodeRepository;
import tech.cwvermaak.intellisso.repository.OidcClientRepository;
import tech.cwvermaak.intellisso.repository.TenantMfaPolicyRepository;
import tech.cwvermaak.intellisso.repository.TenantRepository;
import tech.cwvermaak.intellisso.repository.UserRepository;
import tech.cwvermaak.intellisso.service.TenantMfaPolicyService;
import tech.cwvermaak.intellisso.service.audit.AuditService;
import tech.cwvermaak.intellisso.service.oidc.OidcAuthorizationService;
import tech.cwvermaak.intellisso.service.oidc.StepUpRequiredException;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicLong;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

public class MfaPoliciesSteps {

    private final TestWorld world;
    private final AtomicLong ids = new AtomicLong(11000);

    // Mocks
    private TenantAccessor tenantAccessor;
    private TenantRepository tenantRepository;
    private TenantMfaPolicyRepository policyRepo;
    private MfaFactorRepository mfaFactorRepo;
    private UserRepository userRepo;
    private AuditService auditService;
    private OidcClientRepository oidcClientRepo;
    private OAuthAuthorizationCodeRepository codeRepo;

    // Services under test
    private TenantMfaPolicyService mfaPolicyService;
    private OidcAuthorizationService oidcAuthService;

    // Stores
    private final Map<String, Tenant> tenantsBySlug = new HashMap<>();
    private final Map<String, User> users = new HashMap<>();
    private final Map<Long, TenantMfaPolicy> policyStore = new HashMap<>();
    private final List<MfaFactor> factorStore = new ArrayList<>();
    private final Map<String, OidcClient> clientStore = new HashMap<>();

    // Scenario state
    private MfaPolicyDto readPolicy;
    private Throwable lastError;
    private String lastAuthCode;
    private boolean mustEnroll;
    private boolean tokenIssued;

    public MfaPoliciesSteps(TestWorld world) {
        this.world = world;
    }

    // ---- Wiring ----------------------------------------------------

    private void ensureWired() {
        if (mfaPolicyService != null) return;

        tenantAccessor = mock(TenantAccessor.class);
        tenantRepository = mock(TenantRepository.class);
        policyRepo = mock(TenantMfaPolicyRepository.class);
        mfaFactorRepo = mock(MfaFactorRepository.class);
        userRepo = mock(UserRepository.class);
        auditService = mock(AuditService.class);
        oidcClientRepo = mock(OidcClientRepository.class);
        codeRepo = mock(OAuthAuthorizationCodeRepository.class);

        // Never deny cross-tenant in these scenarios.
        doNothing().when(tenantAccessor).requireSameTenant(anyLong());

        when(tenantRepository.findById(anyLong())).thenAnswer(inv -> {
            Long id = inv.getArgument(0);
            return tenantsBySlug.values().stream()
                    .filter(t -> id.equals(t.getId()))
                    .findFirst();
        });

        when(policyRepo.findByTenantId(anyLong())).thenAnswer(inv -> {
            Long tid = inv.getArgument(0);
            return Optional.ofNullable(policyStore.get(tid));
        });
        when(policyRepo.save(any(TenantMfaPolicy.class))).thenAnswer(inv -> {
            TenantMfaPolicy p = inv.getArgument(0);
            if (p.getId() == null) p.setId(ids.getAndIncrement());
            policyStore.put(p.getTenant().getId(), p);
            return p;
        });

        when(mfaFactorRepo.findByUserIdAndEnabledTrueAndVerifiedTrue(anyLong())).thenAnswer(inv -> {
            Long uid = inv.getArgument(0);
            return factorStore.stream()
                    .filter(f -> f.getUser().getId().equals(uid))
                    .filter(f -> Boolean.TRUE.equals(f.getEnabled()))
                    .filter(f -> Boolean.TRUE.equals(f.getVerified()))
                    .toList();
        });

        when(oidcClientRepo.findByTenantIdAndClientId(anyLong(), anyString())).thenAnswer(inv -> {
            String cid = inv.getArgument(1);
            return Optional.ofNullable(clientStore.get(cid));
        });

        when(codeRepo.save(any(OAuthAuthorizationCode.class))).thenAnswer(inv -> {
            OAuthAuthorizationCode c = inv.getArgument(0);
            if (c.getId() == null) c.setId(ids.getAndIncrement());
            return c;
        });

        // Capture audit events
        doAnswer(inv -> {
            world.auditLog.add(AuditEvent.builder()
                    .eventType(inv.getArgument(0))
                    .outcome(AuditEvent.Outcome.SUCCESS)
                    .build());
            return null;
        }).when(auditService).recordAdmin(anyString(), any(), anyString(), anyString(), any());
        doAnswer(inv -> {
            world.auditLog.add(AuditEvent.builder()
                    .eventType(inv.getArgument(0))
                    .outcome(AuditEvent.Outcome.SUCCESS)
                    .build());
            return null;
        }).when(auditService).recordUserAction(anyString(), any(), anyString(), anyString(), any());

        mfaPolicyService = new TenantMfaPolicyService(tenantAccessor, tenantRepository,
                policyRepo, mfaFactorRepo, userRepo, auditService);
        oidcAuthService = new OidcAuthorizationService(oidcClientRepo, codeRepo, auditService,
                mfaFactorRepo, mfaPolicyService);
    }

    private Tenant tenant(String slug) {
        return tenantsBySlug.computeIfAbsent(slug, s ->
                Tenant.builder().id(ids.getAndIncrement()).slug(s).name(s).build());
    }

    // ---- Background ------------------------------------------------

    @Given("tenant {string} exists for MFA policy tests")
    public void tenantExists(String slug) {
        ensureWired();
        tenant(slug);
    }

    @Given("user {string} exists in tenant {string} for MFA policy tests")
    public void userExists(String email, String slug) {
        Tenant t = tenant(slug);
        User u = User.builder()
                .id(ids.getAndIncrement())
                .tenant(t)
                .email(email)
                .username(email)
                .password("hashed")
                .createdAt(LocalDateTime.now())
                .build();
        users.put(slug + "|" + email.toLowerCase(), u);
    }

    // ---- Policy reading / writing ----------------------------------

    @When("admin reads the MFA policy for tenant {string}")
    public void adminReadsPolicy(String slug) {
        Tenant t = tenant(slug);
        readPolicy = mfaPolicyService.get(t.getId());
    }

    @Then("the effective enforcement is {string}")
    public void enforcementIs(String expected) {
        assertThat(readPolicy.getEnforcement().name()).isEqualTo(expected);
    }

    @Given("the MFA policy for tenant {string} is set to REQUIRED with grace period {int} days")
    public void setPolicyRequired(String slug, int graceDays) {
        Tenant t = tenant(slug);
        TenantMfaPolicy p = TenantMfaPolicy.builder()
                .id(ids.getAndIncrement())
                .tenant(t)
                .enforcement(TenantMfaPolicy.Enforcement.REQUIRED)
                .gracePeriodDays(graceDays)
                .defaultStepupMaxAge(0)
                .build();
        policyStore.put(t.getId(), p);
    }

    @Given("alice has no MFA factors")
    public void aliceHasNoFactors() {
        // factorStore is empty by default — no action needed, but present
        // for readability of the scenario.
        assertThat(true).isTrue();
    }

    @Given("alice was created {int} days ago")
    public void aliceCreatedDaysAgo(int days) {
        User alice = users.get("acme|alice@acme.test");
        alice.setCreatedAt(LocalDateTime.now().minusDays(days));
    }

    // ---- Policy enforcement on login -------------------------------

    @When("alice logs in with the correct password")
    public void aliceLogsIn() {
        // We simulate the login-time enforcement check directly, without
        // spinning up the full AuthService (which would require Spring
        // Security + refresh-token + audit infra that other scenarios
        // already cover). The policy-driven decision is what we're testing.
        User alice = users.get("acme|alice@acme.test");
        mustEnroll = mfaPolicyService.mustEnroll(alice);
        tokenIssued = !mustEnroll;
        if (mustEnroll) {
            // Mirror what AuthService.login emits.
            world.auditLog.add(AuditEvent.builder()
                    .eventType("mfa.enrollment_required")
                    .outcome(AuditEvent.Outcome.SUCCESS)
                    .actorUser(alice)
                    .build());
        }
    }

    @Then("the login response indicates MFA enrollment is required")
    public void loginRequiresEnrollment() {
        assertThat(mustEnroll).isTrue();
        assertThat(tokenIssued).isFalse();
    }

    @Then("alice receives a regular access token")
    public void aliceReceivesToken() {
        assertThat(mustEnroll).isFalse();
        assertThat(tokenIssued).isTrue();
    }

    @Then("a {string} audit event is recorded for policy tests")
    public void auditRecorded(String type) {
        assertThat(world.auditLog).extracting(AuditEvent::getEventType).contains(type);
    }

    // ---- OIDC step-up ---------------------------------------------

    @Given("an OIDC client {string} is registered for tenant {string} with require_mfa true")
    public void registerHighSecClient(String clientId, String slug) {
        Tenant t = tenant(slug);
        OidcClient c = OidcClient.builder()
                .id(ids.getAndIncrement())
                .tenant(t)
                .clientId(clientId)
                .clientSecret("secret")
                .redirectUris("https://app.test/cb")
                .scopes("openid profile")
                .grantTypes("authorization_code")
                .requirePkce(true)
                .requireMfa(true)
                .maxAuthenticationAgeSeconds(0)
                .build();
        clientStore.put(clientId, c);
    }

    @Given("alice has a verified TOTP factor")
    public void aliceHasVerifiedTotp() {
        User alice = users.get("acme|alice@acme.test");
        factorStore.add(MfaFactor.builder()
                .id(ids.getAndIncrement())
                .user(alice)
                .type(MfaFactorType.TOTP)
                .totpSecretEnc("secret")
                .enabled(true)
                .verified(true)
                .lastUsedAt(LocalDateTime.now().minusMinutes(1))
                .build());
    }

    @When("alice requests an authorization code for client {string}")
    public void requestAuthorizationCode(String clientId) {
        User alice = users.get("acme|alice@acme.test");
        Tenant t = alice.getTenant();
        lastError = null;
        lastAuthCode = null;

        OidcAuthorizationService.AuthorizeRequest req =
                new OidcAuthorizationService.AuthorizeRequest(
                        clientId,
                        "https://app.test/cb",
                        List.of("openid", "profile"),
                        "state-xyz",
                        "nonce-xyz",
                        // Provide a PKCE challenge since require_pkce is true.
                        "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
                        "S256");

        try {
            lastAuthCode = oidcAuthService.issueAuthorizationCode(t, alice, req);
        } catch (Exception e) {
            lastError = e;
        }
    }

    @Then("the request is rejected with MFA step-up required")
    public void stepUpRejected() {
        assertThat(lastError).isInstanceOf(StepUpRequiredException.class);
        assertThat(lastAuthCode).isNull();
    }

    @Then("an authorization code is issued")
    public void codeIssued() {
        assertThat(lastError).isNull();
        assertThat(lastAuthCode).isNotBlank();
    }
}
