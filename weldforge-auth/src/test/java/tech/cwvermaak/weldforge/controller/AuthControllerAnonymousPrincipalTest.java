package tech.cwvermaak.weldforge.controller;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.http.ResponseEntity;
import tech.cwvermaak.weldforge.repository.UserRepository;
import tech.cwvermaak.weldforge.service.AuthService;
import tech.cwvermaak.weldforge.service.EmailVerificationService;
import tech.cwvermaak.weldforge.service.PasswordResetService;
import tech.cwvermaak.weldforge.service.TenantSamlService;
import tech.cwvermaak.weldforge.service.TenantService;
import tech.cwvermaak.weldforge.service.TenantVerificationService;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;

/**
 * The self-service endpoints are reachable without authentication, so an
 * expired or unreadable bearer token arrives as the {@code "anonymousUser"}
 * principal rather than being rejected by the filter chain.
 *
 * <p>Two of them looked that principal up as an email and threw when nobody
 * matched, which Spring rendered as <b>500</b>. A 500 is not something a client
 * can act on: the Wellspring dashboard's proxy retries after a 401 and refreshes
 * the session, so it never retried, and the user was shown "an unexpected error
 * occurred" on a page that only needed a newer token.</p>
 */
@DisplayName("/api/auth — an expired session is 401, never 500")
class AuthControllerAnonymousPrincipalTest {

    private UserRepository users;
    private AuthController controller;

    @BeforeEach
    void setUp() {
        users = mock(UserRepository.class);
        controller = new AuthController(
                mock(AuthService.class),
                mock(EmailVerificationService.class),
                mock(PasswordResetService.class),
                users,
                mock(TenantService.class),
                mock(TenantSamlService.class),
                mock(TenantVerificationService.class));
    }

    @ParameterizedTest(name = "principal = \"{0}\"")
    @NullSource
    @ValueSource(strings = {"", "   ", "anonymousUser"})
    @DisplayName("GET /me answers 401 without touching the database")
    void currentUserRejectsAnonymous(String principal) {
        ResponseEntity<?> result = controller.currentUser(principal);

        assertThat(result.getStatusCode().value()).isEqualTo(401);
        // The lookup is what threw. Reaching it at all is the bug, so assert on
        // the cause rather than only on the status.
        verifyNoInteractions(users);
    }

    @ParameterizedTest(name = "principal = \"{0}\"")
    @NullSource
    @ValueSource(strings = {"", "   ", "anonymousUser"})
    @DisplayName("POST /logout-all answers 401 rather than revoking nothing loudly")
    void logoutAllRejectsAnonymous(String principal) {
        ResponseEntity<?> result = controller.logoutAll(principal);

        assertThat(result.getStatusCode().value()).isEqualTo(401);
        verifyNoInteractions(users);
    }
}
