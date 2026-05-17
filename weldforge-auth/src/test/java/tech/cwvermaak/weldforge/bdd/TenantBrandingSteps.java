package tech.cwvermaak.weldforge.bdd;

import io.cucumber.datatable.DataTable;
import io.cucumber.java.en.Given;
import io.cucumber.java.en.Then;
import io.cucumber.java.en.When;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import jakarta.persistence.EntityNotFoundException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import tech.cwvermaak.weldforge.config.tenant.TenantAccessor;
import tech.cwvermaak.weldforge.config.tenant.TenantContext;
import tech.cwvermaak.weldforge.model.Tenant;
import tech.cwvermaak.weldforge.model.dto.RegisterRequestDto;
import tech.cwvermaak.weldforge.model.dto.TenantBrandingDto;
import tech.cwvermaak.weldforge.model.dto.TenantDto;
import tech.cwvermaak.weldforge.repository.PasswordResetTokenRepository;
import tech.cwvermaak.weldforge.repository.TenantRepository;
import tech.cwvermaak.weldforge.repository.TenantSocialProviderRepository;
import tech.cwvermaak.weldforge.repository.UserRepository;
import tech.cwvermaak.weldforge.service.AuthService;
import tech.cwvermaak.weldforge.service.EmailVerificationService;
import tech.cwvermaak.weldforge.service.JwtService;
import tech.cwvermaak.weldforge.service.PasswordResetService;
import tech.cwvermaak.weldforge.service.TenantMfaPolicyService;
import tech.cwvermaak.weldforge.service.TenantService;
import tech.cwvermaak.weldforge.service.audit.AuditService;
import tech.cwvermaak.weldforge.service.crm.CrmProvisioningService;
import tech.cwvermaak.weldforge.service.mail.MailService;
import tech.cwvermaak.weldforge.service.ldap.LdapUpstreamService;
import tech.cwvermaak.weldforge.service.mfa.MfaService;
import tech.cwvermaak.weldforge.service.security.AccountLockoutService;
import tech.cwvermaak.weldforge.service.security.PasswordPolicyService;
import tech.cwvermaak.weldforge.service.security.RefreshTokenService;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * BDD steps for {@code tenant_branding.feature}. Exercises {@link TenantService}
 * with a mocked repository — the controller is a thin pass-through, the global
 * {@code @ExceptionHandler(EntityNotFoundException.class)} returns 404 for
 * the unknown-slug case, so 200/404 are modelled by "did the call succeed
 * vs throw EntityNotFoundException" here.
 */
public class TenantBrandingSteps {

    private final TestWorld world;

    private TenantRepository tenantRepository;
    private TenantSocialProviderRepository providerRepository;
    private UserRepository userRepository;
    private AuditService auditService;
    private TenantAccessor tenantAccessor;
    private TenantService service;

    private AuthService authService;
    private PasswordResetService passwordResetService;

    private final Map<String, Tenant> store = new HashMap<>();
    private final AtomicLong idSeq = new AtomicLong(7000);

    private TenantBrandingDto lastBranding;
    private Throwable lastError;
    private Integer lastStatus;
    private Integer lastRegisterStatus;
    private Integer lastForgotPasswordStatus;

    public TenantBrandingSteps(TestWorld world) {
        this.world = world;
    }

    private void ensureWired() {
        if (service != null) return;

        tenantRepository = mock(TenantRepository.class);
        providerRepository = mock(TenantSocialProviderRepository.class);
        userRepository = mock(UserRepository.class);
        auditService = mock(AuditService.class);
        tenantAccessor = mock(TenantAccessor.class);

        // requireAnyAdmin / requireTenantAdmin / requireSuperAdmin / requireSameTenant
        // are void — Mockito's default is a no-op, so nothing extra to stub.
        when(tenantAccessor.isSuperAdmin()).thenReturn(true);

        when(tenantRepository.findBySlug(any())).thenAnswer(inv ->
                java.util.Optional.ofNullable(store.get((String) inv.getArgument(0))));
        when(tenantRepository.findById(any())).thenAnswer(inv -> {
            Long id = inv.getArgument(0);
            return store.values().stream().filter(t -> id.equals(t.getId())).findFirst();
        });
        when(tenantRepository.save(any(Tenant.class))).thenAnswer(inv -> {
            Tenant t = inv.getArgument(0);
            if (t.getId() == null) t.setId(idSeq.getAndIncrement());
            store.put(t.getSlug(), t);
            return t;
        });

        service = new TenantService(tenantAccessor, tenantRepository, providerRepository,
                                    userRepository, auditService);
    }

    private void ensureAuthWired() {
        ensureWired();
        if (authService != null) return;

        // AuthService has a long collaborator list. For the disabled-tenant
        // case we never reach any of these — the flag check throws first.
        authService = new AuthService(
                userRepository,
                tenantRepository,
                mock(PasswordEncoder.class),
                mock(JwtService.class),
                mock(MfaService.class),
                auditService,
                mock(AccountLockoutService.class),
                mock(PasswordPolicyService.class),
                mock(RefreshTokenService.class),
                mock(EmailVerificationService.class),
                mock(TenantMfaPolicyService.class),
                new SimpleMeterRegistry(),
                mock(LdapUpstreamService.class),
                mock(CrmProvisioningService.class));

        passwordResetService = new PasswordResetService(
                userRepository,
                tenantRepository,
                mock(PasswordResetTokenRepository.class),
                mock(PasswordEncoder.class),
                mock(PasswordPolicyService.class),
                auditService,
                mock(RefreshTokenService.class),
                mock(MailService.class));
    }

    @Given("a tenant {string} exists for branding with display name {string}")
    public void aTenantExistsForBranding(String slug, String displayName) {
        ensureWired();
        Tenant t = Tenant.builder()
                .id(idSeq.getAndIncrement())
                .slug(slug)
                .name(slug)
                .displayName(displayName)
                .enabled(true)
                .registrationEnabled(true)
                .passwordRecoveryEnabled(true)
                .emailVerificationRequired(true)
                .createdAt(LocalDateTime.now())
                .updatedAt(LocalDateTime.now())
                .build();
        store.put(slug, t);
        TenantContext.set(slug, t.getId(), true);
    }

    @Given("an admin sets the branding for tenant {string} to:")
    public void adminSetsBranding(String slug, DataTable table) {
        ensureWired();
        Tenant t = store.get(slug);
        assertThat(t).isNotNull();
        Map<String, Object> branding = new HashMap<>();
        for (Map.Entry<String, String> row : table.asMap(String.class, String.class).entrySet()) {
            branding.put(row.getKey(), row.getValue());
        }
        TenantDto patch = TenantDto.builder().branding(branding).build();
        try {
            service.updateTenant(t.getId(), patch);
        } catch (Throwable e) {
            lastError = e;
        }
    }

    @Given("an admin disables registration for tenant {string}")
    public void adminDisablesRegistration(String slug) {
        ensureWired();
        Tenant t = store.get(slug);
        assertThat(t).isNotNull();
        TenantDto patch = TenantDto.builder().registrationEnabled(false).build();
        service.updateTenant(t.getId(), patch);
    }

    @Given("an admin disables password recovery for tenant {string}")
    public void adminDisablesPasswordRecovery(String slug) {
        ensureWired();
        Tenant t = store.get(slug);
        assertThat(t).isNotNull();
        TenantDto patch = TenantDto.builder().passwordRecoveryEnabled(false).build();
        service.updateTenant(t.getId(), patch);
    }

    @When("the public branding endpoint is queried for tenant {string}")
    public void publicBrandingQueried(String slug) {
        ensureWired();
        try {
            lastBranding = service.getBrandingForSlug(slug);
            lastStatus = 200;
            lastError = null;
        } catch (EntityNotFoundException e) {
            lastBranding = null;
            lastStatus = 404;
            lastError = e;
        }
    }

    @Then("the branding response status is {int}")
    public void brandingResponseStatus(int expected) {
        assertThat(lastStatus).isEqualTo(expected);
    }

    @Then("the branding response field {string} equals {word}")
    public void brandingResponseFieldEquals(String field, String expected) {
        assertThat(lastBranding).isNotNull();
        Object actual = switch (field) {
            case "registrationEnabled" -> lastBranding.getRegistrationEnabled();
            case "passwordRecoveryEnabled" -> lastBranding.getPasswordRecoveryEnabled();
            case "displayName" -> lastBranding.getDisplayName();
            case "slug" -> lastBranding.getSlug();
            default -> throw new IllegalArgumentException("unknown field " + field);
        };
        assertThat(String.valueOf(actual)).isEqualToIgnoringCase(expected);
    }

    @Then("the branding response payload contains {string} with value {string}")
    public void brandingPayloadContains(String key, String value) {
        assertThat(lastBranding).isNotNull();
        assertThat(lastBranding.getBranding())
                .as("branding payload should contain %s=%s", key, value)
                .isNotNull()
                .containsEntry(key, value);
    }

    @When("a user tries to register on tenant {string}")
    public void userTriesToRegister(String slug) {
        ensureAuthWired();
        TenantContext.set(slug, store.get(slug) != null ? store.get(slug).getId() : null, false);
        RegisterRequestDto req = new RegisterRequestDto("alice", "alice@" + slug + ".test", "S3cretP@ssw0rd!");
        try {
            authService.register(req, mock(HttpServletRequest.class), mock(HttpServletResponse.class));
            lastRegisterStatus = 200;
            lastError = null;
        } catch (EntityNotFoundException e) {
            lastRegisterStatus = 404;
            lastError = e;
        } catch (Throwable e) {
            // Any other failure: treat as 500-ish; tests will assert against 404/200 only.
            lastRegisterStatus = 500;
            lastError = e;
        }
    }

    @Then("the register response status is {int}")
    public void registerResponseStatus(int expected) {
        assertThat(lastRegisterStatus)
                .as("register status (last error: %s)", lastError)
                .isEqualTo(expected);
    }

    @When("the forgot-password endpoint is called for tenant {string}")
    public void forgotPasswordCalled(String slug) {
        ensureAuthWired();
        TenantContext.set(slug, store.get(slug) != null ? store.get(slug).getId() : null, false);
        try {
            passwordResetService.requestReset("ghost@" + slug + ".test");
            lastForgotPasswordStatus = 200;
            lastError = null;
        } catch (EntityNotFoundException e) {
            lastForgotPasswordStatus = 404;
            lastError = e;
        } catch (Throwable e) {
            lastForgotPasswordStatus = 500;
            lastError = e;
        }
    }

    @Then("the forgot-password response status is {int}")
    public void forgotPasswordResponseStatus(int expected) {
        assertThat(lastForgotPasswordStatus)
                .as("forgot-password status (last error: %s)", lastError)
                .isEqualTo(expected);
    }

    public TestWorld world() {
        return world;
    }

    static {
        // Step classes are instantiated by Cucumber with no security context;
        // make sure stale auth from a previous scenario doesn't leak.
        SecurityContextHolder.clearContext();
    }
}
