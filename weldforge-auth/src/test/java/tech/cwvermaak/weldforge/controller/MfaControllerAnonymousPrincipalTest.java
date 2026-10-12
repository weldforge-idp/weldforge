package tech.cwvermaak.weldforge.controller;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import tech.cwvermaak.weldforge.repository.UserRepository;
import tech.cwvermaak.weldforge.service.AuthService;
import tech.cwvermaak.weldforge.service.mfa.BackupCodeService;
import tech.cwvermaak.weldforge.service.mfa.MfaService;
import tech.cwvermaak.weldforge.service.mfa.WebAuthnService;
import tech.cwvermaak.weldforge.service.security.AccountLockoutService;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;

/**
 * The same defect {@link AuthControllerAnonymousPrincipalTest} covers, in the
 * controller that was missed when it was fixed.
 *
 * <p>An expired or revoked bearer token reaches a controller as the
 * {@code "anonymousUser"} principal rather than being refused by the filter
 * chain. Looking that up as an email found nobody and threw
 * {@code IllegalStateException}, which the global handler rendered as
 * <b>500</b>.</p>
 *
 * <p>The status is the whole point, not the tidiness. The admin portal's
 * interceptor answers a 401 by refreshing the session and replaying the
 * request; it has no answer for a 500. On 2026-10-12 that left a user who
 * had just signed in with Google sitting on a Security page reading
 * "Failed to load factors: An unexpected error occurred", holding a token
 * whose session had been revoked, with the recovery built for exactly that
 * case never reached.</p>
 */
@DisplayName("/api/auth/mfa — an expired session is 401, never 500")
class MfaControllerAnonymousPrincipalTest {

    private UserRepository users;
    private MfaController controller;

    @BeforeEach
    void setUp() {
        users = mock(UserRepository.class);
        controller = new MfaController(
                mock(MfaService.class),
                mock(BackupCodeService.class),
                mock(WebAuthnService.class),
                users,
                mock(AuthService.class),
                mock(AccountLockoutService.class));
    }

    @ParameterizedTest(name = "principal = \"{0}\"")
    @NullSource
    @ValueSource(strings = {"", "   ", "anonymousUser"})
    @DisplayName("GET /mfa/factors refuses without touching the database")
    void listFactorsRejectsAnonymous(String principal) {
        assertThatThrownBy(() -> controller.listFactors(principal))
                .isInstanceOf(InsufficientAuthenticationException.class);

        // Reaching the lookup at all is the bug: it is what threw the 500.
        verifyNoInteractions(users);
    }

    @ParameterizedTest(name = "principal = \"{0}\"")
    @NullSource
    @ValueSource(strings = {"", "   ", "anonymousUser"})
    @DisplayName("GET /mfa/backup-codes refuses without touching the database")
    void backupCodesRejectAnonymous(String principal) {
        assertThatThrownBy(() -> controller.backupCodeStatus(principal))
                .isInstanceOf(InsufficientAuthenticationException.class);

        verifyNoInteractions(users);
    }

    @Test
    @DisplayName("an authenticated session naming no account here is also 401, not 500")
    void unknownAccountIsAlsoUnauthenticated() {
        // The session is real but names someone this tenant does not have.
        // Re-authenticating is the remedy, so it is an authentication
        // failure, not a server fault.
        assertThatThrownBy(() -> controller.listFactors("ghost@example.test"))
                .isInstanceOf(InsufficientAuthenticationException.class);
    }
}
