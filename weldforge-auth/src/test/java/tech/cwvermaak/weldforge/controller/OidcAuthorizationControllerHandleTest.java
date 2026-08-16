package tech.cwvermaak.weldforge.controller;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.ResponseEntity;
import tech.cwvermaak.weldforge.service.oidc.OidcAuthorizationException;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * B-OIDC-2: the /authorize error handler must redirect protocol errors back to
 * a validated redirect_uri (RFC 6749 §4.1.2.1) while keeping pre-validation
 * errors as a JSON 400. handle() depends only on the exception, so the
 * controller is constructed with null collaborators.
 */
class OidcAuthorizationControllerHandleTest {

    private final OidcAuthorizationController controller =
            new OidcAuthorizationController(null, null, null, null, null, null, null, null);

    @Test
    @DisplayName("a redirectable error becomes a 302 to redirect_uri carrying error + state")
    void redirectableError_redirectsWithErrorAndState() {
        var ex = new OidcAuthorizationException("unsupported_response_type",
                "Only response_type=code is supported", "https://rp.example.com/cb", "xyz123");

        ResponseEntity<?> resp = controller.handle(ex);

        assertThat(resp.getStatusCode().value()).isEqualTo(302);
        String loc = resp.getHeaders().getLocation().toString();
        assertThat(loc).startsWith("https://rp.example.com/cb?");
        assertThat(loc).contains("error=unsupported_response_type");
        assertThat(loc).contains("state=xyz123");
        assertThat(resp.getBody()).isNull();
    }

    @Test
    @DisplayName("a redirectable error with no state omits the state param")
    void redirectableError_noState() {
        var ex = new OidcAuthorizationException("access_denied", "denied",
                "https://rp.example.com/cb", null);

        ResponseEntity<?> resp = controller.handle(ex);

        assertThat(resp.getStatusCode().value()).isEqualTo(302);
        String loc = resp.getHeaders().getLocation().toString();
        assertThat(loc).contains("error=access_denied");
        assertThat(loc).doesNotContain("state=");
    }

    @Test
    @DisplayName("a pre-validation error (unknown client) stays a JSON 400, never redirects")
    void nonRedirectableError_is400Json() {
        var ex = new OidcAuthorizationException("invalid_client", "Unknown client_id for this tenant");

        ResponseEntity<?> resp = controller.handle(ex);

        assertThat(resp.getStatusCode().value()).isEqualTo(400);
        assertThat(resp.getHeaders().getLocation()).isNull();
        assertThat(resp.getBody()).isInstanceOf(java.util.Map.class);
        @SuppressWarnings("unchecked")
        var body = (java.util.Map<String, String>) resp.getBody();
        assertThat(body).containsEntry("error", "invalid_client");
        assertThat(body).containsKey("error_description");
    }

    @Test
    @DisplayName("invalid redirect_uri is not redirectable — would otherwise be an open redirect")
    void invalidRedirectUri_notRedirectable() {
        var ex = new OidcAuthorizationException("invalid_request",
                "redirect_uri does not match a registered URI");

        assertThat(ex.isRedirectable()).isFalse();
        assertThat(controller.handle(ex).getStatusCode().value()).isEqualTo(400);
    }
}
