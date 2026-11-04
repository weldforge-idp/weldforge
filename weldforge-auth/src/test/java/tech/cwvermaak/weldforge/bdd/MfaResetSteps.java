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
import tech.cwvermaak.weldforge.service.mfa.LastFactorProtectedException;
import tech.cwvermaak.weldforge.service.security.AccountLockoutService;
import tech.cwvermaak.weldforge.service.security.FailedLoginRecorder;
import tech.cwvermaak.weldforge.model.dto.MfaVerifyRequestDto;
import tech.cwvermaak.weldforge.service.audit.AuditEventTypes;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.OptionalLong;
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
    private AccountLockoutService lockoutService;
    private FailedLoginRecorder failedLoginRecorder;

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
        lockoutService = mock(AccountLockoutService.class);
        failedLoginRecorder = mock(FailedLoginRecorder.class);
        mfa = new MfaService(factorRepo, backupRepo, userRepo, jwtService, totpService,
                backupCodeService, webAuthnService, passwordEncoder, auditService, twilioService,
                mock(tech.cwvermaak.weldforge.repository.ConsumedMfaChallengeRepository.class),
                lockoutService, failedLoginRecorder);

        // The recorder is mocked, so mirror its audit write into the world or
        // the refused-password scenario would have nothing to assert on.
        doAnswer(inv -> {
            User actor = inv.getArgument(0);
            world.auditLog.add(AuditEvent.builder()
                    .eventType(AuditEventTypes.AUTH_MFA_RESET_DENIED)
                    .outcome(AuditEvent.Outcome.FAILURE)
                    .actorUser(actor)
                    .actorEmail(actor != null ? actor.getEmail() : null)
                    .build());
            return null;
        }).when(failedLoginRecorder).badResetPassword(any());

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
                .totpSecretEnc("enc-secret")
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

        // The step-up guard (F60) asks which factors are verified AND enabled.
        // Unstubbed this returns empty, which silently routes every scenario
        // down the "account holds nothing" branch and would make the new
        // scenarios pass without the guard ever running.
        when(factorRepo.findByUserIdAndEnabledTrueAndVerifiedTrue(u.getId()))
                .thenAnswer(inv -> world.factorsByUser.get(u.getId()).stream()
                        .filter(f -> Boolean.TRUE.equals(f.getEnabled())
                                && Boolean.TRUE.equals(f.getVerified()))
                        .toList());

        when(factorRepo.findByIdAndUserId(anyLong(), eq(u.getId())))
                .thenAnswer(inv -> world.factorsByUser.get(u.getId()).stream()
                        .filter(f -> f.getId().equals(inv.getArgument(0)))
                        .findFirst());

        when(factorRepo.findByUserIdAndType(eq(u.getId()), any()))
                .thenAnswer(inv -> world.factorsByUser.get(u.getId()).stream()
                        .filter(f -> f.getType() == inv.getArgument(1))
                        .toList());

        doAnswer(inv -> {
            world.factorsByUser.get(u.getId()).remove((MfaFactor) inv.getArgument(0));
            return null;
        }).when(factorRepo).delete(any(MfaFactor.class));

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
            mfa.selfReset(world.currentActor, "wrong", null);
        } catch (Throwable t) {
            world.lastError = t;
        }
    }

    @When("I request a self-service MFA reset with the correct password and nothing else")
    public void selfResetCorrectPasswordOnly() {
        when(passwordEncoder.matches(eq("correct"), any())).thenReturn(true);
        try {
            world.lastRemoved = mfa.selfReset(world.currentActor, "correct", null);
        } catch (Throwable t) {
            world.lastError = t;
        }
    }

    @When("I request a self-service MFA reset with the correct password and a valid code")
    public void selfResetCorrectPasswordAndCode() {
        when(passwordEncoder.matches(eq("correct"), any())).thenReturn(true);
        MfaFactor totp = world.factorsByUser.get(world.currentActor.getId()).stream()
                .filter(f -> f.getType() == MfaFactorType.TOTP).findFirst().orElseThrow();
        when(totpService.matchingStep(totp.getTotpSecretEnc(), "123456"))
                .thenReturn(OptionalLong.of(5810000L));
        MfaVerifyRequestDto proof = MfaVerifyRequestDto.builder()
                .type(MfaFactorType.TOTP).code("123456").build();
        world.lastRemoved = mfa.selfReset(world.currentActor, "correct", proof);
    }

    @When("I request a self-service MFA reset with the correct password and a backup code")
    public void selfResetCorrectPasswordAndBackupCode() {
        when(passwordEncoder.matches(eq("correct"), any())).thenReturn(true);
        when(backupCodeService.consume(eq(world.currentActor), eq("RECOVER-1"))).thenReturn(true);
        MfaVerifyRequestDto proof = MfaVerifyRequestDto.builder().backupCode("RECOVER-1").build();
        world.lastRemoved = mfa.selfReset(world.currentActor, "correct", proof);
    }

    @When("I try to delete my only verified factor directly")
    public void deleteOnlyVerifiedFactor() {
        MfaFactor only = world.factorsByUser.get(world.currentActor.getId()).stream()
                .filter(f -> Boolean.TRUE.equals(f.getVerified())).findFirst().orElseThrow();
        try {
            mfa.deleteFactor(world.currentActor, only.getId());
        } catch (Throwable t) {
            world.lastError = t;
        }
    }

    @Given("I have started enrolling a second factor but not finished it")
    public void halfFinishedEnrollment() {
        MfaFactor pending = MfaFactor.builder()
                .id(ids.getAndIncrement())
                .user(world.currentActor)
                .type(MfaFactorType.TOTP)
                .label("New authenticator")
                .enabled(true)
                .verified(false)
                .build();
        world.factorsByUser.get(world.currentActor.getId()).add(pending);
        world.pendingFactorId = pending.getId();
    }

    @When("I cancel that enrollment")
    public void cancelEnrollment() {
        try {
            mfa.deleteFactor(world.currentActor, world.pendingFactorId);
        } catch (Throwable t) {
            world.lastError = t;
        }
    }

    @Then("the enrollment is cancelled and my verified factor is untouched")
    public void enrollmentCancelled() {
        assertThat(world.lastError).isNull();
        List<MfaFactor> remaining = world.factorsByUser.get(world.currentActor.getId());
        assertThat(remaining).noneMatch(f -> f.getId().equals(world.pendingFactorId));
        assertThat(remaining).anyMatch(f -> Boolean.TRUE.equals(f.getVerified()));
    }

    @Then("the removal is refused because it is my last factor")
    public void removalRefusedLastFactor() {
        assertThat(world.lastError).isInstanceOf(LastFactorProtectedException.class);
        assertThat(world.lastError.getMessage()).contains("MFA reset");
        assertThat(world.factorsByUser.get(world.currentActor.getId())).isNotEmpty();
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
