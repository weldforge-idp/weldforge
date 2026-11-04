package tech.cwvermaak.weldforge.bdd;

import io.cucumber.java.en.Given;
import io.cucumber.java.en.Then;
import io.cucumber.java.en.When;
import tech.cwvermaak.weldforge.model.AuditEvent;
import tech.cwvermaak.weldforge.model.Tenant;
import tech.cwvermaak.weldforge.model.User;
import tech.cwvermaak.weldforge.repository.UserRepository;
import tech.cwvermaak.weldforge.service.audit.AuditService;
import tech.cwvermaak.weldforge.service.security.AccountLockedException;
import tech.cwvermaak.weldforge.service.security.AccountLockoutProperties;
import tech.cwvermaak.weldforge.service.security.AccountLockoutService;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import tech.cwvermaak.weldforge.repository.TenantRepository;
import tech.cwvermaak.weldforge.service.AuthService;
import tech.cwvermaak.weldforge.service.security.RefreshTokenService;
import tech.cwvermaak.weldforge.service.security.FailedLoginRecorder;
import tech.cwvermaak.weldforge.service.security.PasswordPolicyService;
import tech.cwvermaak.weldforge.config.tenant.TenantContext;

import java.time.LocalDateTime;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class AccountLockoutSteps {

    private final TestWorld world;

    private UserRepository userRepository;
    private AuditService auditService;
    private AccountLockoutProperties props;
    private AccountLockoutService service;
    private User alice;

    // B-AUTH-6 (F61): the change-password scenarios drive the REAL
    // AuthService.changePassword against the real AccountLockoutService and
    // the real FailedLoginRecorder. Only the repositories and the two
    // collaborators changePassword does not reason about are mocked. Driving
    // the real method is the point: what F61 changes is the ORDER of the lock
    // check and the password compare, and a test that called the recorder
    // directly would assert the parts while proving nothing about the
    // sequence.
    private AuthService authService;
    private CountingEncoder encoder;
    private Tenant aliceTenant;
    private String aliceCurrentHash;

    /** A real bcrypt encoder that counts matches() calls, so "the current
     *  password was never compared" is an assertion rather than an assumption. */
    private static final class CountingEncoder extends BCryptPasswordEncoder {
        int matchCount;
        @Override
        public boolean matches(CharSequence raw, String encoded) {
            matchCount++;
            return super.matches(raw, encoded);
        }
    }

    public AccountLockoutSteps(TestWorld world) {
        this.world = world;
    }

    @Given("lockout is configured with {int} attempts and a {int} minute window")
    public void lockoutConfigured(int attempts, int minutes) {
        userRepository = mock(UserRepository.class);
        auditService = mock(AuditService.class);
        props = new AccountLockoutProperties();
        props.setMaxAttempts(attempts);
        props.setLockMinutes(minutes);
        service = new AccountLockoutService(userRepository, props, auditService);

        // Whenever AccountLockoutService records an event, capture it so
        // scenarios can assert on the audit trail later.
        doAnswer(inv -> {
            User actor = inv.getArgument(1);
            world.auditLog.add(AuditEvent.builder()
                    .eventType(inv.getArgument(0))
                    .outcome(AuditEvent.Outcome.SUCCESS)
                    .actorUser(actor)
                    .actorEmail(actor != null ? actor.getEmail() : null)
                    .build());
            return null;
        }).when(auditService).recordUserAction(any(), any(), any(), any(), any());
    }

    @Given("user {string} exists with a fresh counter")
    public void userExists(String email) {
        Tenant t = Tenant.builder().id(1L).slug("acme").name("Acme").build();
        alice = User.builder()
                .id(42L)
                .tenant(t)
                .email(email)
                .failedLoginAttempts(0)
                .build();
        world.users.put(email, alice);
        world.currentActor = alice;
        aliceTenant = t;
    }

    // --- B-AUTH-6 (F61): the change-password path -------------------------

    /**
     * Builds AuthService with the three real collaborators the invariant
     * depends on, and nulls for the fourteen changePassword never touches.
     * The audit mock is the one the Background already wired into
     * {@code world.auditLog}, so password-change failures land in the same
     * trail the other scenarios assert on.
     */
    private void ensureAuthService() {
        if (authService != null) return;
        encoder = new CountingEncoder();
        aliceCurrentHash = encoder.encode("current-correct");
        // encode() does not call matches(); reset so the counter only reflects
        // what the scenario itself provokes.
        encoder.matchCount = 0;
        alice.setPassword(aliceCurrentHash);

        TenantRepository tenantRepository = mock(TenantRepository.class);
        when(tenantRepository.findBySlug("acme")).thenReturn(Optional.of(aliceTenant));
        when(userRepository.findByTenant_SlugAndEmailIgnoreCase("acme", "alice@acme.test"))
                .thenReturn(Optional.of(alice));

        FailedLoginRecorder recorder =
                new FailedLoginRecorder(auditService, service, new SimpleMeterRegistry());
        PasswordPolicyService policy = mock(PasswordPolicyService.class);
        RefreshTokenService refreshTokens = mock(RefreshTokenService.class);

        authService = new AuthService(
                userRepository, tenantRepository, encoder, null, null, auditService,
                service, policy, refreshTokens, null, null, null, null, null, null,
                recorder, null, null);

        TenantContext.set("acme");
    }

    private void attemptChange(String currentPassword) {
        ensureAuthService();
        world.lastError = null;
        try {
            authService.changePassword("alice@acme.test", currentPassword, "N3w-passw0rd!");
            world.lastResult = "changed";
        } catch (RuntimeException e) {
            world.lastResult = "refused";
            world.lastError = e;
        }
    }

    @When("alice tries to change her password with the wrong current password {int} times")
    public void wrongCurrentPasswordNTimes(int n) {
        for (int i = 0; i < n; i++) attemptChange("definitely-not-it");
    }

    @When("alice tries to change her password with the correct current password")
    public void changeWithCorrectCurrentPassword() {
        attemptChange("current-correct");
    }

    @When("alice changes her password with the correct current password")
    public void changesWithCorrectCurrentPassword() {
        attemptChange("current-correct");
    }

    @Then("the failed attempt counter reads {int}")
    public void counterReads(int n) {
        assertThat(alice.getFailedLoginAttempts()).isEqualTo(n);
    }

    @Then("the last change attempt was refused as locked")
    public void lastChangeRefusedAsLocked() {
        assertThat(world.lastResult).isEqualTo("refused");
        assertThat(world.lastError)
                .as("a locked account must answer 423 (AccountLockedException), "
                        + "not the vague 401 a wrong password gets")
                .isInstanceOf(AccountLockedException.class);
    }

    @Then("the current password was never compared")
    public void currentPasswordNeverCompared() {
        assertThat(encoder.matchCount)
                .as("the lock must be checked BEFORE the password compare, so a "
                        + "locked account cannot be used as an oracle and bcrypt's "
                        + "runtime is not itself a signal")
                .isZero();
    }

    @Then("the password is unchanged")
    public void passwordUnchanged() {
        assertThat(alice.getPassword()).isEqualTo(aliceCurrentHash);
    }

    @Then("the password change succeeds")
    public void passwordChangeSucceeds() {
        assertThat(world.lastError).isNull();
        assertThat(world.lastResult).isEqualTo("changed");
        assertThat(encoder.matches("N3w-passw0rd!", alice.getPassword())).isTrue();
    }

    @When("alice enters the wrong password {int} times")
    public void wrongPasswordNTimes(int n) {
        for (int i = 0; i < n; i++) service.recordFailure(alice);
    }

    @When("alice enters the correct password")
    public void correctPassword() {
        try {
            service.ensureNotLocked(alice);
            service.recordSuccess(alice);
            world.lastResult = "success";
        } catch (AccountLockedException e) {
            world.lastError = e;
        }
    }

    @Then("the login succeeds")
    public void loginSucceeds() {
        assertThat(world.lastResult).isEqualTo("success");
    }

    @Then("the failed attempt counter is reset")
    public void counterReset() {
        assertThat(alice.getFailedLoginAttempts()).isZero();
        assertThat(alice.getLockedUntil()).isNull();
    }

    @Then("the account is not locked")
    public void accountNotLocked() {
        assertThat(alice.getLockedUntil()).isNull();
    }

    @Then("the account is locked")
    public void accountLocked() {
        assertThat(alice.getLockedUntil()).isNotNull();
        assertThat(alice.getLockedUntil()).isAfter(LocalDateTime.now());
    }

    @Then("an {string} audit event is recorded for alice")
    public void auditEventForAlice(String type) {
        assertThat(world.auditLog)
                .anySatisfy(e -> {
                    assertThat(e.getEventType()).isEqualTo(type);
                    assertThat(e.getActorEmail()).isEqualTo("alice@acme.test");
                });
    }

    @Given("alice is locked until the future")
    public void aliceIsLocked() {
        alice.setLockedUntil(LocalDateTime.now().plusMinutes(5));
    }

    @Then("the attempt is rejected as locked")
    public void rejectedAsLocked() {
        assertThat(world.lastError).isInstanceOf(AccountLockedException.class);
    }
}
