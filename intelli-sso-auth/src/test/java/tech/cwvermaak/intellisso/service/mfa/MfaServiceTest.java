package tech.cwvermaak.intellisso.service.mfa;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;
import tech.cwvermaak.intellisso.model.MfaFactor;
import tech.cwvermaak.intellisso.model.MfaFactorType;
import tech.cwvermaak.intellisso.model.Tenant;
import tech.cwvermaak.intellisso.model.User;
import tech.cwvermaak.intellisso.repository.BackupCodeRepository;
import tech.cwvermaak.intellisso.repository.MfaFactorRepository;
import tech.cwvermaak.intellisso.repository.UserRepository;
import tech.cwvermaak.intellisso.service.JwtService;
import tech.cwvermaak.intellisso.service.audit.AuditEventTypes;
import tech.cwvermaak.intellisso.service.audit.AuditService;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
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

        mfa = new MfaService(factorRepo, backupRepo, userRepo, jwtService,
                totpService, backupCodeService, webAuthnService, passwordEncoder, auditService);

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

        assertThatThrownBy(() -> mfa.selfReset(user, "wrong"))
                .isInstanceOf(BadCredentialsException.class);

        // Nothing wiped; no audit written.
        verify(factorRepo, never()).deleteAll(any());
        verify(backupRepo, never()).deleteAllByUserId(any());
        verify(auditService, never()).recordUserAction(eq(AuditEventTypes.MFA_SELF_RESET),
                any(), any(), any(), any());
    }

    @Test
    @DisplayName("selfReset clears every factor and backup code when the password matches")
    void selfReset_correctPassword_wipesFactorsAndAudits() {
        when(passwordEncoder.matches("right", user.getPassword())).thenReturn(true);
        MfaFactor totp = MfaFactor.builder().id(10L).user(user).type(MfaFactorType.TOTP).build();
        MfaFactor key  = MfaFactor.builder().id(11L).user(user).type(MfaFactorType.WEBAUTHN).build();
        when(factorRepo.findByUserId(42L)).thenReturn(List.of(totp, key));

        int removed = mfa.selfReset(user, "right");

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
    @DisplayName("hasVerifiedFactor only counts enabled + verified rows")
    void hasVerifiedFactor_looksForEnabledAndVerified() {
        when(factorRepo.findByUserIdAndEnabledTrueAndVerifiedTrue(42L))
                .thenReturn(List.of(MfaFactor.builder().id(1L).type(MfaFactorType.TOTP).build()));

        assertThat(mfa.hasVerifiedFactor(user)).isTrue();

        when(factorRepo.findByUserIdAndEnabledTrueAndVerifiedTrue(42L)).thenReturn(List.of());
        assertThat(mfa.hasVerifiedFactor(user)).isFalse();
    }
}
