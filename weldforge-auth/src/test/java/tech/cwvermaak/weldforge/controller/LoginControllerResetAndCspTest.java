package tech.cwvermaak.weldforge.controller;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import tech.cwvermaak.weldforge.config.security.ContentSecurityPolicy;
import tech.cwvermaak.weldforge.config.tenant.PublicHostProperties;
import tech.cwvermaak.weldforge.repository.TenantRepository;
import tech.cwvermaak.weldforge.service.AuthService;
import tech.cwvermaak.weldforge.service.PasswordResetService;
import tech.cwvermaak.weldforge.service.security.PasswordPolicyProperties;
import tech.cwvermaak.weldforge.service.security.PasswordPolicyViolation;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

/**
 * The hosted login pages after Sprint 6.
 *
 * <p>CONF-7.1: the reset page used to pre-check a stale "at least 8
 * characters" rule and to report every failure -- a breached password
 * included -- as an expired link. It now defers to the policy and says why.
 *
 * <p>CONF-7.2: every page renders through one shell whose only inline block is
 * the stylesheet, and it must carry the response's CSP nonce.
 */
class LoginControllerResetAndCspTest {

    private final PasswordResetService resetService = mock(PasswordResetService.class);
    private final PasswordPolicyProperties policy = new PasswordPolicyProperties();

    private LoginController controller() {
        PublicHostProperties publicHost = new PublicHostProperties();
        publicHost.setBaseDomain("sso.weldforge.org");
        return new LoginController(mock(AuthService.class), mock(TenantRepository.class),
                resetService, publicHost, policy);
    }

    @AfterEach
    void clearRequest() {
        RequestContextHolder.resetRequestAttributes();
    }

    // ---- CONF-7.1: reset -------------------------------------------------

    @Test
    @DisplayName("A policy failure names the policy's reasons, not an expired link")
    void policy_failure_shows_reasons() {
        doThrow(new PasswordPolicyViolation(List.of(
                "must not appear in a known data breach, and this one does; choose a different password")))
                .when(resetService).resetPassword("tok", "password1234");

        ResponseEntity<?> response = controller().resetSubmit("tok", "password1234", "password1234");

        assertThat(response.getStatusCode().value()).isEqualTo(200);
        assertThat(response.getBody().toString())
                .contains("Choose a different password")
                .contains("known data breach")
                .doesNotContain("invalid or has expired");
    }

    @Test
    @DisplayName("After a policy failure the form is re-rendered with the same token, so the link still works")
    void policy_failure_keeps_the_token() {
        doThrow(new PasswordPolicyViolation(List.of("at least 12 characters")))
                .when(resetService).resetPassword(anyString(), anyString());

        ResponseEntity<?> response = controller().resetSubmit("tok-abc", "short", "short");

        assertThat(response.getBody().toString()).contains("name='token' value='tok-abc'");
    }

    @Test
    @DisplayName("Length is the policy's to judge: no local 8-character pre-check any more")
    void no_local_length_precheck() {
        controller().resetSubmit("tok", "short", "short");

        // Reaches the service, which applies the configured policy.
        verify(resetService).resetPassword("tok", "short");
    }

    @Test
    @DisplayName("Mismatched confirmation never reaches the service")
    void mismatch() {
        ResponseEntity<?> response = controller().resetSubmit("tok", "correct horse battery", "correct horse");

        assertThat(response.getBody().toString()).contains("Passwords do not match.");
        verifyNoInteractions(resetService);
    }

    @Test
    @DisplayName("An invalid or expired token still says so")
    void invalid_token() {
        doThrow(new IllegalArgumentException("Invalid or expired reset token"))
                .when(resetService).resetPassword(anyString(), anyString());

        ResponseEntity<?> response = controller().resetSubmit("tok", "correct horse battery", "correct horse battery");

        assertThat(response.getBody().toString()).contains("Reset link is invalid or has expired");
    }

    @Test
    @DisplayName("Success bounces to sign-in")
    void success_redirects() {
        ResponseEntity<?> response = controller().resetSubmit("tok", "correct horse battery", "correct horse battery");

        assertThat(response.getStatusCode().value()).isEqualTo(303);
        assertThat(response.getHeaders().getLocation()).hasToString("/login/?reset=1");
    }

    @Test
    @DisplayName("The reset form states the configured rule, not a hard-coded one")
    void hint_follows_configuration() {
        policy.setMinLength(14);

        String html = controller().resetForm("tok", null).getBody();

        assertThat(html)
                .contains("At least 14 characters")
                .contains("minlength='14'")
                .contains("maxlength='72'")
                .contains("known data")
                .doesNotContain("minlength='8'");
    }

    // ---- CONF-7.2: nonce on the shell ------------------------------------

    @Test
    @DisplayName("Every hosted page's stylesheet carries this request's CSP nonce")
    void stylesheet_carries_request_nonce() {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/login/");
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));
        String nonce = ContentSecurityPolicy.nonce(request);

        LoginController c = controller();
        for (String html : List.of(
                c.form(null, null).getBody(),
                c.forgotForm(null).getBody(),
                c.forgotForm("1").getBody(),
                c.resetForm("tok", null).getBody())) {
            assertThat(html).contains("<style nonce=\"" + nonce + "\">");
            assertThat(html).doesNotContainPattern("<style>");
            assertThat(html).doesNotContain("<script");
            assertThat(html).doesNotContainPattern("\\son[a-z]+\\s*=");
            assertThat(html).doesNotContainPattern("\\sstyle\\s*=");
        }
    }

    @Test
    @DisplayName("Outside a request (no nonce to share) the shell renders without one rather than failing")
    void no_request_no_nonce() {
        String html = controller().form(null, null).getBody();

        assertThat(html).contains("<style>").doesNotContain("nonce=");
    }
}
