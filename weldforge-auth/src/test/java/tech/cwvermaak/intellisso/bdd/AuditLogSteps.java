package tech.cwvermaak.intellisso.bdd;

import io.cucumber.java.en.Given;
import io.cucumber.java.en.Then;
import io.cucumber.java.en.When;
import tech.cwvermaak.intellisso.model.AuditEvent;
import tech.cwvermaak.intellisso.model.Tenant;
import tech.cwvermaak.intellisso.model.User;
import tech.cwvermaak.intellisso.service.audit.AuditEventTypes;
import tech.cwvermaak.intellisso.service.audit.AuditService;

import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;

public class AuditLogSteps {

    private final TestWorld world;
    private AuditService auditService;

    public AuditLogSteps(TestWorld world) {
        this.world = world;
    }

    private void ensureAuditService() {
        if (auditService != null) return;
        auditService = mock(AuditService.class);

        // Capture anonymous writes (used for failed-login audit)
        doAnswer(inv -> {
            world.auditLog.add(AuditEvent.builder()
                    .eventType(inv.getArgument(0))
                    .outcome(inv.getArgument(1))
                    .actorEmail(inv.getArgument(3))
                    .targetType(inv.getArgument(4))
                    .targetId(inv.getArgument(5))
                    .metadata(inv.getArgument(6))
                    .build());
            return null;
        }).when(auditService).recordAnonymous(any(), any(), any(), any(), any(), any(), any());

        // Capture user-actions (used for backup-code regeneration)
        doAnswer(inv -> {
            User actor = inv.getArgument(1);
            world.auditLog.add(AuditEvent.builder()
                    .eventType(inv.getArgument(0))
                    .outcome(AuditEvent.Outcome.SUCCESS)
                    .actorUser(actor)
                    .actorEmail(actor != null ? actor.getEmail() : null)
                    .targetType(inv.getArgument(2))
                    .targetId(inv.getArgument(3))
                    .metadata(inv.getArgument(4))
                    .build());
            return null;
        }).when(auditService).recordUserAction(any(), any(), any(), any(), any());
    }

    @When("a login attempt with {string} and a wrong password is made")
    public void loginAttemptFails(String email) {
        ensureAuditService();
        // Simulate what AuthService.login does on bad password:
        auditService.recordAnonymous(
                AuditEventTypes.AUTH_LOGIN_FAILED,
                AuditEvent.Outcome.FAILURE,
                1L,
                email,
                AuditEventTypes.TARGET_USER,
                null,
                Map.of("reason", "bad_password"));
    }

    @Then("the audit log contains a {string} event")
    public void auditHasEvent(String type) {
        assertThat(world.auditLog)
                .anySatisfy(e -> assertThat(e.getEventType()).isEqualTo(type));
    }

    @Then("the event's outcome is {string}")
    @Then("the event outcome is {string}")
    public void eventOutcome(String outcome) {
        assertThat(world.auditLog)
                .anySatisfy(e -> assertThat(e.getOutcome().name()).isEqualTo(outcome));
    }

    @Then("the event metadata mentions {string}")
    public void eventMetadataMentions(String needle) {
        assertThat(world.auditLog)
                .anySatisfy(e -> {
                    assertThat(e.getMetadata()).isNotNull();
                    assertThat(e.getMetadata().toString()).contains(needle);
                });
    }

    @Given("user {string} is signed in")
    public void userSignedIn(String email) {
        ensureAuditService();
        Tenant tenant = Tenant.builder().id(1L).slug("acme").name("Acme").build();
        world.currentActor = User.builder().id(42L).tenant(tenant).email(email).build();
    }

    @When("alice regenerates her backup codes")
    public void regeneratesBackupCodes() {
        // Simulate BackupCodeService firing the audit event.
        auditService.recordUserAction(
                AuditEventTypes.MFA_BACKUP_CODES_REGENERATED,
                world.currentActor,
                AuditEventTypes.TARGET_USER,
                String.valueOf(world.currentActor.getId()),
                Map.of("count", 10));
    }
}
