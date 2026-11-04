package tech.cwvermaak.weldforge.service.mfa;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;
import tech.cwvermaak.weldforge.model.MfaFactor;
import tech.cwvermaak.weldforge.model.MfaFactorType;
import tech.cwvermaak.weldforge.model.Tenant;
import tech.cwvermaak.weldforge.model.User;
import tech.cwvermaak.weldforge.repository.BackupCodeRepository;
import tech.cwvermaak.weldforge.repository.MfaFactorRepository;
import tech.cwvermaak.weldforge.repository.UserRepository;
import tech.cwvermaak.weldforge.service.JwtService;
import tech.cwvermaak.weldforge.service.audit.AuditEventTypes;
import tech.cwvermaak.weldforge.service.audit.AuditService;
import tech.cwvermaak.weldforge.model.dto.MfaVerifyRequestDto;
import tech.cwvermaak.weldforge.service.security.AccountLockoutService;
import tech.cwvermaak.weldforge.service.security.AccountLockedException;
import tech.cwvermaak.weldforge.service.security.FailedLoginRecorder;

import java.util.List;
import java.util.Optional;
import java.util.OptionalLong;
import java.time.LocalDateTime;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.catchThrowable;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

class MfaServiceTest {

    private MfaFactorRepository factorRepo;
    private BackupCodeRepository backupRepo;
    private UserRepository userRepo;
    private JwtService jwtService;
    private TotpService totpService;
    private BackupCodeService backupCodeService;
    private WebAuthnService webAuthnService;
    private PasswordEncoder passwordEncoder;
    private AuditService auditService;
    private tech.cwvermaak.weldforge.repository.ConsumedMfaChallengeRepository consumedRepo;
    private AccountLockoutService lockoutService;
    private FailedLoginRecorder failedLoginRecorder;

    private MfaService mfa;
    private User user;

    @BeforeEach
    void setUp() {
        factorRepo = mock(MfaFactorRepository.class);
        backupRepo = mock(BackupCodeRepository.class);
        userRepo = mock(UserRepository.class);
        jwtService = mock(JwtService.class);
        totpService = mock(TotpService.class);
        backupCodeService = mock(BackupCodeService.class);
        webAuthnService = mock(WebAuthnService.class);
        passwordEncoder = mock(PasswordEncoder.class);
        auditService = mock(AuditService.class);
        consumedRepo = mock(tech.cwvermaak.weldforge.repository.ConsumedMfaChallengeRepository.class);
        var twilioService = mock(tech.cwvermaak.weldforge.service.TwilioService.class);

        lockoutService = mock(AccountLockoutService.class);
        failedLoginRecorder = mock(FailedLoginRecorder.class);

        mfa = new MfaService(factorRepo, backupRepo, userRepo, jwtService,
                totpService, backupCodeService, webAuthnService, passwordEncoder, auditService,
                twilioService, consumedRepo, lockoutService, failedLoginRecorder);

        Tenant t = Tenant.builder().id(1L).slug("acme").name("Acme").build();
        user = User.builder()
                .id(42L)
                .tenant(t)
                .email("alice@acme.test")
                .password("$2a$04$hashed")
                .build();
    }

    @Test
    @DisplayName("selfReset refuses when the submitted password does not match")
    void selfReset_wrongPassword_denied() {
        when(passwordEncoder.matches("wrong", user.getPassword())).thenReturn(false);

        assertThatThrownBy(() -> mfa.selfReset(user, "wrong", null))
                .isInstanceOf(BadCredentialsException.class);

        // Nothing wiped; no success audit written.
        verify(factorRepo, never()).deleteAll(any());
        verify(backupRepo, never()).deleteAllByUserId(any());
        verify(auditService, never()).recordUserAction(eq(AuditEventTypes.MFA_SELF_RESET),
                any(), any(), any(), any());
        // B-AUTH-5 (F60): the guess is now recorded and feeds the account
        // lockout. Before F60 a wrong password here left no trace at all,
        // which is what made the endpoint a silent password oracle.
        verify(failedLoginRecorder).badResetPassword(user);
    }

    @Test
    @DisplayName("selfReset with no verified factor held still clears on the password alone")
    void selfReset_correctPassword_wipesFactorsAndAudits() {
        // findByUserIdAndEnabledTrueAndVerifiedTrue is unstubbed, so the user
        // holds nothing verified: an account that is already unprotected, where
        // demanding a factor proof would be demanding the impossible (F60
        // decision 2). The factor rows here are unverified leftovers.
        when(passwordEncoder.matches("right", user.getPassword())).thenReturn(true);
        MfaFactor totp = MfaFactor.builder().id(10L).user(user).type(MfaFactorType.TOTP).build();
        MfaFactor key  = MfaFactor.builder().id(11L).user(user).type(MfaFactorType.WEBAUTHN).build();
        when(factorRepo.findByUserId(42L)).thenReturn(List.of(totp, key));

        int removed = mfa.selfReset(user, "right", null);

        assertThat(removed).isEqualTo(2);
        verify(factorRepo, atLeastOnce()).deleteAll(any());
        verify(backupRepo).deleteAllByUserId(42L);
        verify(auditService).recordUserAction(eq(AuditEventTypes.MFA_SELF_RESET),
                eq(user), eq(AuditEventTypes.TARGET_USER), eq("42"), any());
    }

    @Test
    @DisplayName("adminReset wipes the target's factors and audits with the actor as the caller")
    void adminReset_wipesTargetAndAuditsActor() {
        Tenant tenant = user.getTenant();
        User actor = User.builder().id(1L).tenant(tenant).email("admin@acme.test").build();
        User target = User.builder().id(42L).tenant(tenant).email("alice@acme.test").build();
        when(factorRepo.findByUserId(42L)).thenReturn(List.of(
                MfaFactor.builder().id(100L).user(target).type(MfaFactorType.TOTP).build()));

        int removed = mfa.adminReset(actor, target);

        assertThat(removed).isEqualTo(1);
        verify(backupRepo).deleteAllByUserId(42L);

        ArgumentCaptor<java.util.Map<String, Object>> metaCaptor = ArgumentCaptor.forClass(java.util.Map.class);
        verify(auditService).recordAdmin(eq(AuditEventTypes.MFA_ADMIN_RESET),
                eq(actor),
                eq(AuditEventTypes.TARGET_USER),
                eq("42"),
                metaCaptor.capture());
        assertThat(metaCaptor.getValue()).containsEntry("target_email", "alice@acme.test");
        assertThat(metaCaptor.getValue()).containsEntry("removed", 1);
    }

    @Test
    @DisplayName("verifyChallenge(TOTP) accepts a fresh time-step then rejects the same step as a replay")
    void verifyTotp_antiReplay() {
        MfaFactor totp = MfaFactor.builder()
                .id(10L).user(user).type(MfaFactorType.TOTP)
                .totpSecretEnc("SECRET").enabled(true).verified(true).build();
        when(factorRepo.findByUserIdAndType(42L, MfaFactorType.TOTP)).thenReturn(List.of(totp));
        when(totpService.matchingStep("SECRET", "123456")).thenReturn(java.util.OptionalLong.of(100L));

        var req = tech.cwvermaak.weldforge.model.dto.MfaVerifyRequestDto.builder()
                .type(MfaFactorType.TOTP).code("123456").build();

        // First use of step 100 succeeds and records it on the factor.
        assertThat(mfa.verifyChallenge(user, req)).isTrue();
        assertThat(totp.getLastTotpStep()).isEqualTo(100L);

        // Replaying the same code (same step) is now rejected.
        assertThat(mfa.verifyChallenge(user, req)).isFalse();
    }

    @Test
    @DisplayName("resolveChallenge rejects a challenge token whose jti was already consumed")
    void resolveChallenge_rejectsConsumedJti() {
        io.jsonwebtoken.Claims claims = mock(io.jsonwebtoken.Claims.class);
        when(jwtService.parse("tok")).thenReturn(claims);
        when(jwtService.isMfaChallenge(claims)).thenReturn(true);
        when(claims.getId()).thenReturn("JTI-1");
        when(consumedRepo.existsById("JTI-1")).thenReturn(true);

        assertThatThrownBy(() -> mfa.resolveChallenge("tok"))
                .isInstanceOf(org.springframework.security.access.AccessDeniedException.class);
        verify(userRepo, never()).findById(any());
    }

    @Test
    @DisplayName("consumeChallenge records the jti so the token can't be reused")
    void consumeChallenge_recordsJti() {
        io.jsonwebtoken.Claims claims = mock(io.jsonwebtoken.Claims.class);
        when(jwtService.parse("tok")).thenReturn(claims);
        when(claims.getId()).thenReturn("JTI-2");
        when(claims.getExpiration()).thenReturn(new java.util.Date(System.currentTimeMillis() + 300_000));
        when(consumedRepo.existsById("JTI-2")).thenReturn(false);

        mfa.consumeChallenge("tok");

        ArgumentCaptor<tech.cwvermaak.weldforge.model.ConsumedMfaChallenge> captor =
                ArgumentCaptor.forClass(tech.cwvermaak.weldforge.model.ConsumedMfaChallenge.class);
        verify(consumedRepo).save(captor.capture());
        assertThat(captor.getValue().getJti()).isEqualTo("JTI-2");
    }

    @Test
    @DisplayName("consumeChallenge is a no-op for a legacy token without a jti")
    void consumeChallenge_noJti_noop() {
        io.jsonwebtoken.Claims claims = mock(io.jsonwebtoken.Claims.class);
        when(jwtService.parse("tok")).thenReturn(claims);
        when(claims.getId()).thenReturn(null);

        mfa.consumeChallenge("tok");

        verify(consumedRepo, never()).save(any());
    }

    @Test
    @DisplayName("hasVerifiedFactor only counts enabled + verified rows")
    void hasVerifiedFactor_looksForEnabledAndVerified() {
        when(factorRepo.findByUserIdAndEnabledTrueAndVerifiedTrue(42L))
                .thenReturn(List.of(MfaFactor.builder().id(1L).type(MfaFactorType.TOTP).build()));

        assertThat(mfa.hasVerifiedFactor(user)).isTrue();

        when(factorRepo.findByUserIdAndEnabledTrueAndVerifiedTrue(42L)).thenReturn(List.of());
        assertThat(mfa.hasVerifiedFactor(user)).isFalse();
    }

    // -- B-AUTH-5 / F60: removing MFA requires proving you still hold it ----
    //
    // These assert the invariant rather than the plumbing: an account cannot go
    // from MFA-protected to unprotected without the password AND a current
    // factor proof arriving together.

    /** Give the user one verified, enabled TOTP factor. */
    private MfaFactor protectedByTotp() {
        MfaFactor totp = MfaFactor.builder()
                .id(10L).user(user).type(MfaFactorType.TOTP)
                .enabled(true).verified(true).totpSecretEnc("enc-secret")
                .build();
        when(factorRepo.findByUserIdAndEnabledTrueAndVerifiedTrue(42L)).thenReturn(List.of(totp));
        when(factorRepo.findByUserId(42L)).thenReturn(List.of(totp));
        return totp;
    }

    @Test
    @DisplayName("selfReset refuses the password alone once a verified factor is held")
    void selfReset_passwordAlone_refusedWhenProtected() {
        when(passwordEncoder.matches("right", user.getPassword())).thenReturn(true);
        protectedByTotp();

        assertThatThrownBy(() -> mfa.selfReset(user, "right", null))
                .isInstanceOf(BadCredentialsException.class);

        // This is the whole point of the sprint: the correct password is no
        // longer sufficient to turn MFA off.
        verify(factorRepo, never()).deleteAll(any());
        verify(backupRepo, never()).deleteAllByUserId(any());
        verify(auditService).recordUserAction(eq(AuditEventTypes.MFA_SELF_RESET_DENIED),
                eq(user), any(), any(), any());
    }

    @Test
    @DisplayName("selfReset clears everything on password plus a valid TOTP code")
    void selfReset_passwordAndTotp_wipes() {
        when(passwordEncoder.matches("right", user.getPassword())).thenReturn(true);
        MfaFactor totp = protectedByTotp();
        when(factorRepo.findByUserIdAndType(42L, MfaFactorType.TOTP)).thenReturn(List.of(totp));
        when(totpService.matchingStep("enc-secret", "123456")).thenReturn(OptionalLong.of(5810000L));

        MfaVerifyRequestDto proof = MfaVerifyRequestDto.builder()
                .type(MfaFactorType.TOTP).code("123456").build();
        int removed = mfa.selfReset(user, "right", proof);

        assertThat(removed).isEqualTo(1);
        verify(backupRepo).deleteAllByUserId(42L);
        verify(auditService).recordUserAction(eq(AuditEventTypes.MFA_SELF_RESET),
                eq(user), eq(AuditEventTypes.TARGET_USER), eq("42"), any());
    }

    @Test
    @DisplayName("selfReset accepts a backup code as proof, which is the lost-authenticator path")
    void selfReset_passwordAndBackupCode_wipes() {
        when(passwordEncoder.matches("right", user.getPassword())).thenReturn(true);
        protectedByTotp();
        when(backupCodeService.consume(user, "ABCD-1234")).thenReturn(true);

        MfaVerifyRequestDto proof = MfaVerifyRequestDto.builder().backupCode("ABCD-1234").build();
        int removed = mfa.selfReset(user, "right", proof);

        // The reason this must work: the user who needs a reset is usually the
        // user whose authenticator is gone. Requiring an authenticator proof
        // would leave them no self-service path at all.
        assertThat(removed).isEqualTo(1);
        verify(backupRepo).deleteAllByUserId(42L);
    }

    @Test
    @DisplayName("selfReset refuses a wrong code and records it as a challenge failure")
    void selfReset_wrongCode_refusedAndRecorded() {
        when(passwordEncoder.matches("right", user.getPassword())).thenReturn(true);
        MfaFactor totp = protectedByTotp();
        when(factorRepo.findByUserIdAndType(42L, MfaFactorType.TOTP)).thenReturn(List.of(totp));
        when(totpService.matchingStep("enc-secret", "000000")).thenReturn(OptionalLong.empty());

        MfaVerifyRequestDto proof = MfaVerifyRequestDto.builder()
                .type(MfaFactorType.TOTP).code("000000").build();
        assertThatThrownBy(() -> mfa.selfReset(user, "right", proof))
                .isInstanceOf(BadCredentialsException.class);

        verify(factorRepo, never()).deleteAll(any());
        // A wrong code is the same event as a wrong code at /mfa/verify, so it
        // feeds the challenge-failure trail, not the password lockout.
        verify(auditService).recordUserAction(eq(AuditEventTypes.MFA_SELF_RESET_DENIED),
                eq(user), any(), any(), any());
        verify(failedLoginRecorder, never()).badResetPassword(any());
    }

    @Test
    @DisplayName("a wrong password and a wrong code are indistinguishable to the caller")
    void selfReset_bothFailures_lookIdentical() {
        // Otherwise the endpoint confirms a password independently of a factor,
        // which is the oracle this sprint set out to close.
        when(passwordEncoder.matches("wrong", user.getPassword())).thenReturn(false);
        MfaFactor totp = protectedByTotp();
        when(factorRepo.findByUserIdAndType(42L, MfaFactorType.TOTP)).thenReturn(List.of(totp));
        when(passwordEncoder.matches("right", user.getPassword())).thenReturn(true);
        when(totpService.matchingStep("enc-secret", "000000")).thenReturn(OptionalLong.empty());

        MfaVerifyRequestDto bad = MfaVerifyRequestDto.builder()
                .type(MfaFactorType.TOTP).code("000000").build();

        String fromBadPassword = catchThrowable(() -> mfa.selfReset(user, "wrong", bad)).getMessage();
        String fromBadCode = catchThrowable(() -> mfa.selfReset(user, "right", bad)).getMessage();

        assertThat(fromBadPassword).isEqualTo(fromBadCode);
    }

    @Test
    @DisplayName("selfReset refuses a locked account before it reads the password")
    void selfReset_lockedAccount_refusedBeforePasswordRead() {
        doThrow(new AccountLockedException(LocalDateTime.now().plusMinutes(15)))
                .when(lockoutService).ensureNotLocked(user);

        assertThatThrownBy(() -> mfa.selfReset(user, "right", null))
                .isInstanceOf(AccountLockedException.class);

        // Without this gate, lockout stops guessing at the front door while
        // this endpoint keeps answering.
        verify(passwordEncoder, never()).matches(any(), any());
        verify(factorRepo, never()).deleteAll(any());
    }

    @Test
    @DisplayName("deleteFactor refuses the last verified factor and names the reset instead")
    void deleteFactor_lastVerifiedFactor_refused() {
        MfaFactor totp = protectedByTotp();
        when(factorRepo.findByIdAndUserId(10L, 42L)).thenReturn(Optional.of(totp));

        assertThatThrownBy(() -> mfa.deleteFactor(user, 10L))
                .isInstanceOf(LastFactorProtectedException.class);

        // The route that asks for no proof must not be a cheaper way to strip
        // MFA than the route built to demand it.
        verify(factorRepo, never()).delete(any());
    }

    @Test
    @DisplayName("deleteFactor still cancels a half-finished enrollment")
    void deleteFactor_unverifiedEnrollment_stillRemoved() {
        // Keyed on verified-and-enabled, not on "the last row": otherwise a
        // user who mistyped a TOTP setup could not back out of it.
        MfaFactor pending = MfaFactor.builder()
                .id(20L).user(user).type(MfaFactorType.TOTP)
                .enabled(true).verified(false)
                .build();
        when(factorRepo.findByIdAndUserId(20L, 42L)).thenReturn(Optional.of(pending));

        mfa.deleteFactor(user, 20L);

        verify(factorRepo).delete(pending);
    }

    @Test
    @DisplayName("deleteFactor still removes a verified factor while another one remains")
    void deleteFactor_oneOfSeveral_stillRemoved() {
        MfaFactor totp = MfaFactor.builder().id(10L).user(user).type(MfaFactorType.TOTP)
                .enabled(true).verified(true).build();
        MfaFactor key = MfaFactor.builder().id(11L).user(user).type(MfaFactorType.WEBAUTHN)
                .enabled(true).verified(true).build();
        when(factorRepo.findByUserIdAndEnabledTrueAndVerifiedTrue(42L))
                .thenReturn(List.of(totp, key));
        when(factorRepo.findByIdAndUserId(10L, 42L)).thenReturn(Optional.of(totp));

        mfa.deleteFactor(user, 10L);

        // Removing this one leaves the account still MFA-protected, so it is
        // not the transition the guard exists to stop. Accepted residual.
        verify(factorRepo).delete(totp);
    }
}
