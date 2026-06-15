package tech.cwvermaak.weldforge.bdd;

import io.cucumber.java.en.Given;
import io.cucumber.java.en.Then;
import io.cucumber.java.en.When;
import org.mockito.ArgumentCaptor;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;
import tech.cwvermaak.weldforge.model.AuditEvent;
import tech.cwvermaak.weldforge.model.MfaFactor;
import tech.cwvermaak.weldforge.model.MfaFactorType;
import tech.cwvermaak.weldforge.model.Tenant;
import tech.cwvermaak.weldforge.model.User;
import tech.cwvermaak.weldforge.repository.BackupCodeRepository;
import tech.cwvermaak.weldforge.repository.MfaFactorRepository;
import tech.cwvermaak.weldforge.repository.UserRepository;
import tech.cwvermaak.weldforge.service.JwtService;
import tech.cwvermaak.weldforge.service.audit.AuditService;
import tech.cwvermaak.weldforge.service.mfa.BackupCodeService;
import tech.cwvermaak.weldforge.service.mfa.MfaService;
import tech.cwvermaak.weldforge.service.mfa.TotpService;
import tech.cwvermaak.weldforge.service.mfa.WebAuthnService;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

public class MfaResetSteps {

    private final TestWorld world;
    private final AtomicLong ids = new AtomicLong(200);

    private MfaFactorRepository factorRepo;
    private BackupCodeRepository backupRepo;
    private UserRepository userRepo;
    private JwtService jwtService;
    private TotpService totpService;
    private BackupCodeService backupCodeService;
    private WebAuthnService webAuthnService;
    private PasswordEncoder passwordEncoder;
    private AuditService auditService;

    private MfaService mfa;

    public MfaResetSteps(TestWorld world) {
        this.world = world;
    }

    private void ensureMfaService() {
        if (mfa != null) return;
        factorRepo = mock(MfaFactorRepository.class);
        backupRepo = mock(BackupCodeRepository.class);
        userRepo = mock(UserRepository.class);
        jwtService = mock(JwtService.class);
        totpService = mock(TotpService.class);
        backupCodeService = mock(BackupCodeService.class);
        webAuthnService = mock(WebAuthnService.class);
        passwordEncoder = mock(PasswordEncoder.class);
        auditService = mock(AuditService.class);
        var twilioService = mock(tech.cwvermaak.weldforge.service.TwilioService.class);
        mfa = new MfaService(factorRepo, backupRepo, userRepo, jwtService, totpService,
                backupCodeService, webAuthnService, passwordEncoder, auditService, twilioService,
                mock(tech.cwvermaak.weldforge.repository.ConsumedMfaChallengeRepository.class));

        // Capture every audit write into world.auditLog for later assertions.
        doAnswer(inv -> {
            String type = inv.getArgument(0);
            User actor = inv.getArgument(1);
            world.auditLog.add(AuditEvent.builder()
                    .eventType(type)
                    .outcome(AuditEvent.Outcome.SUCCESS)
                    .actorUser(actor)
                    .actorEmail(actor != null ? actor.getEmail() : null)
                    .targetType(inv.getArgument(2))
                    .targetId(inv.getArgument(3))
                    .build());
            return null;
        }).when(auditService).recordUserAction(any(), any(), any(), any(), any());

        doAnswer(inv -> {
            String type = inv.getArgument(0);
            User actor = inv.getArgument(1);
            world.auditLog.add(AuditEvent.builder()
                    .eventType(type)
                    .outcome(AuditEvent.Outcome.SUCCESS)
                    .actorUser(actor)
                    .actorEmail(actor != null ? actor.getEmail() : null)
                    .targetType(inv.getArgument(2))
                    .targetId(inv.getArgument(3))
                    .build());
            return null;
        }).when(auditService).recordAdmin(any(), any(), any(), any(), any());
    }

    @Given("user {string} has an enrolled TOTP factor")
    public void userHasTotp(String email) {
        ensureMfaService();
        Tenant tenant = Tenant.builder().id(1L).slug("acme").name("Acme").build();
        User u = User.builder()
                .id(ids.getAndIncrement())
                .tenant(tenant)
                .email(email)
                .password("$2a$04$hashed-password")
                .build();
        world.users.put(email, u);

        MfaFactor totp = MfaFactor.builder()
                .id(ids.getAndIncrement())
                .user(u)
                .type(MfaFactorType.TOTP)
                .label("Authenticator app")
                .enabled(true)
                .verified(true)
                .build();
        world.factorsByUser.put(u.getId(), new ArrayList<>(List.of(totp)));

        // findByUserId returns a fresh snapshot each call — the MfaService
        // calls findByUserId twice in the wipe path (once to count, once to
        // pass to deleteAll) and mutating the shared list while iterating
        // would otherwise trigger a ConcurrentModificationException.
        when(factorRepo.findByUserId(u.getId()))
                .thenAnswer(inv -> new ArrayList<>(world.factorsByUser.get(u.getId())));

        // deleteAll removes from the authoritative list in the world.
        doAnswer(inv -> {
            Iterable<MfaFactor> it = inv.getArgument(0);
            List<MfaFactor> current = world.factorsByUser.get(u.getId());
            List<MfaFactor> snapshot = new ArrayList<>();
            it.forEach(snapshot::add);
            current.removeAll(snapshot);
            return null;
        }).when(factorRepo).deleteAll(any(Iterable.class));
    }

    @Given("I am {string}")
    public void iAm(String email) {
        world.currentActor = world.users.get(email);
    }

    @When("I request a self-service MFA reset with the wrong password")
    public void selfResetWrongPassword() {
        when(passwordEncoder.matches(eq("wrong"), any())).thenReturn(false);
        try {
            mfa.selfReset(world.currentActor, "wrong");
        } catch (Throwable t) {
            world.lastError = t;
        }
    }

    @When("I request a self-service MFA reset with the correct password")
    public void selfResetCorrectPassword() {
        when(passwordEncoder.matches(eq("correct"), any())).thenReturn(true);
        world.lastRemoved = mfa.selfReset(world.currentActor, "correct");
    }

    @Then("the reset is refused with {string}")
    public void resetRefused(String reason) {
        assertThat(world.lastError).isNotNull();
        if ("bad credentials".equals(reason)) {
            assertThat(world.lastError).isInstanceOf(BadCredentialsException.class);
        }
    }

    @Then("my TOTP factor is still present")
    public void totpStillPresent() {
        List<MfaFactor> remaining = world.factorsByUser.get(world.currentActor.getId());
        assertThat(remaining).isNotEmpty();
    }

    @Then("the reset succeeds and reports {int} factor removed")
    public void resetSucceeds(int expected) {
        assertThat(world.lastError).isNull();
        assertThat(world.lastRemoved).isEqualTo(expected);
    }

    @Then("the audit log contains a {string} event for {string}")
    public void auditLogContainsEventFor(String eventType, String email) {
        assertThat(world.auditLog)
                .anySatisfy(e -> {
                    assertThat(e.getEventType()).isEqualTo(eventType);
                    assertThat(e.getActorEmail()).isEqualTo(email);
                });
    }

    @Given("an admin {string} in the same tenant")
    public void anAdminInSameTenant(String email) {
        User anyUser = world.users.values().iterator().next();
        Tenant tenant = anyUser.getTenant();
        User adminUser = User.builder()
                .id(ids.getAndIncrement())
                .tenant(tenant)
                .email(email)
                .build();
        world.users.put(email, adminUser);
        world.currentActor = adminUser;
    }

    @When("the admin resets MFA for {string}")
    public void adminResetsFor(String targetEmail) {
        User target = world.users.get(targetEmail);
        world.lastRemoved = mfa.adminReset(world.currentActor, target);
    }

    @Then("alice's TOTP factor is gone")
    public void alicesTotpGone() {
        User alice = world.users.get("alice@acme.test");
        assertThat(world.factorsByUser.get(alice.getId())).isEmpty();
    }

    @Then("the audit log contains a {string} event recorded by {string}")
    public void auditLogContainsAdminEvent(String eventType, String actorEmail) {
        assertThat(world.auditLog)
                .anySatisfy(e -> {
                    assertThat(e.getEventType()).isEqualTo(eventType);
                    assertThat(e.getActorEmail()).isEqualTo(actorEmail);
                });
    }
}
