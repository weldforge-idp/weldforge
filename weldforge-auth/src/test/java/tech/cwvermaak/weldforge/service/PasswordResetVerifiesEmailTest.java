package tech.cwvermaak.weldforge.service;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.password.PasswordEncoder;
import tech.cwvermaak.weldforge.config.tenant.PublicHostProperties;
import tech.cwvermaak.weldforge.model.PasswordResetToken;
import tech.cwvermaak.weldforge.model.Tenant;
import tech.cwvermaak.weldforge.model.User;
import tech.cwvermaak.weldforge.repository.PasswordResetTokenRepository;
import tech.cwvermaak.weldforge.repository.TenantRepository;
import tech.cwvermaak.weldforge.repository.UserRepository;
import tech.cwvermaak.weldforge.service.audit.AuditService;
import tech.cwvermaak.weldforge.service.mail.MailService;
import tech.cwvermaak.weldforge.service.security.PasswordPolicyService;
import tech.cwvermaak.weldforge.service.security.RefreshTokenService;

import java.time.LocalDateTime;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

/**
 * Completing a reset through an emailed link marks the address verified.
 *
 * <p>It proves what an email-verification link proves, and more recently: the
 * token is mailed to that address and nothing but receiving it there produces
 * it. The service already drew the stronger conclusion from the same evidence
 * — it clears a failed-login lockout because "a completed reset proves account
 * ownership" — while leaving `email_verified` false, so a relying party saw
 * false for an address WeldForge had just reached, and the person did a second
 * mail round to say the same thing again.
 *
 * <p>The boundary is the point of the second test: only the emailed-token path
 * may do this.
 */
class PasswordResetVerifiesEmailTest {

    private UserRepository userRepository;
    private PasswordResetTokenRepository resetTokenRepository;
    private PasswordResetService service;
    private User user;

    @BeforeEach
    void setUp() {
        userRepository = mock(UserRepository.class);
        TenantRepository tenantRepository = mock(TenantRepository.class);
        resetTokenRepository = mock(PasswordResetTokenRepository.class);
        PasswordEncoder encoder = mock(PasswordEncoder.class);
        PasswordPolicyService policy = mock(PasswordPolicyService.class);
        AuditService audit = mock(AuditService.class);
        RefreshTokenService refreshTokens = mock(RefreshTokenService.class);
        MailService mail = mock(MailService.class);
        PublicHostProperties publicHost = new PublicHostProperties();
        publicHost.setBaseDomain("sso.weldforge.org");
        publicHost.setScheme("https");

        when(encoder.encode(anyString())).thenReturn("$2a$12$encoded");
        when(userRepository.save(any(User.class))).thenAnswer(i -> i.getArgument(0));
        when(resetTokenRepository.save(any(PasswordResetToken.class))).thenAnswer(i -> i.getArgument(0));

        Tenant tenant = Tenant.builder().id(1L).slug("counteract-studios")
                .name("counteract-studios").displayName("Counteract Studios").build();

        user = User.builder().id(7L).email("nell.maryke@gmail.com").tenant(tenant)
                .password("$2a$12$old").tokenVersion(0).failedLoginAttempts(3)
                .emailVerified(false).build();

        service = new PasswordResetService(userRepository, tenantRepository,
                resetTokenRepository, encoder, policy, audit, refreshTokens, mail, publicHost);
    }

    private void givenAValidTokenFor(User u) {
        PasswordResetToken token = PasswordResetToken.builder()
                .tenant(u.getTenant()).user(u).tokenHash("ignored")
                .expiresAt(LocalDateTime.now().plusHours(1)).used(false).build();
        when(resetTokenRepository.findByTokenHash(anyString())).thenReturn(Optional.of(token));
    }

    @Test
    @DisplayName("completing an emailed reset marks the address verified")
    void resetVerifiesTheAddress() {
        givenAValidTokenFor(user);
        assertThat(user.isEmailVerified()).isFalse();

        service.resetPassword("some-raw-token", "Tr0ubadour-Mosaic-91!");

        assertThat(user.isEmailVerified())
                .as("the reset token was mailed to this address and had to be received there")
                .isTrue();

        // The things it already did must keep happening.
        assertThat(user.getTokenVersion()).isEqualTo(1);
        assertThat(user.getFailedLoginAttempts()).isZero();
        assertThat(user.getLockedUntil()).isNull();
    }

    @Test
    @DisplayName("an already-verified address stays verified and is not disturbed")
    void alreadyVerifiedStaysVerified() {
        user.setEmailVerified(true);
        givenAValidTokenFor(user);

        service.resetPassword("some-raw-token", "Tr0ubadour-Mosaic-91!");

        assertThat(user.isEmailVerified()).isTrue();
    }

    @Test
    @DisplayName("a spent or expired token verifies nothing")
    void aRefusedResetVerifiesNothing() {
        PasswordResetToken spent = PasswordResetToken.builder()
                .tenant(user.getTenant()).user(user).tokenHash("ignored")
                .expiresAt(LocalDateTime.now().plusHours(1)).used(true).build();
        when(resetTokenRepository.findByTokenHash(anyString())).thenReturn(Optional.of(spent));

        try {
            service.resetPassword("some-raw-token", "Tr0ubadour-Mosaic-91!");
        } catch (IllegalArgumentException expected) {
            // the reuse path
        }

        assertThat(user.isEmailVerified())
                .as("a token that was refused proves nothing about the mailbox")
                .isFalse();
        verify(userRepository, never()).save(any(User.class));
    }
}
