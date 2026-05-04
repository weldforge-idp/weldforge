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

import java.time.LocalDateTime;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;

public class AccountLockoutSteps {

    private final TestWorld world;

    private UserRepository userRepository;
    private AuditService auditService;
    private AccountLockoutProperties props;
    private AccountLockoutService service;
    private User alice;

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
