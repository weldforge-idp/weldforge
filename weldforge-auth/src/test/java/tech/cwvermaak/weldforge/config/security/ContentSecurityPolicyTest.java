package tech.cwvermaak.weldforge.config.security;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import static org.assertj.core.api.Assertions.assertThat;

/** CONF-7.2: the policy itself, and the nonce the pages share with it. */
class ContentSecurityPolicyTest {

    private final ContentSecurityPolicy csp = new ContentSecurityPolicy();

    @Test
    @DisplayName("The header allows same-origin plus this request's nonce, and nothing inline besides")
    void policy_shape() {
        MockHttpServletRequest req = new MockHttpServletRequest("GET", "/t/acme/oauth2/authorize");
        MockHttpServletResponse res = new MockHttpServletResponse();

        csp.writeHeaders(req, res);

        String header = res.getHeader(ContentSecurityPolicy.HEADER);
        String nonce = ContentSecurityPolicy.nonce(req);
        assertThat(header)
                .startsWith("default-src 'self'")
                .contains("script-src 'self' 'nonce-" + nonce + "'")
                .contains("style-src 'self' 'nonce-" + nonce + "'")
                .contains("object-src 'none'")
                .contains("base-uri 'none'")
                .contains("frame-ancestors 'none'")
                .doesNotContain("unsafe-inline")
                .doesNotContain("unsafe-eval")
                // form-action would break the consent redirect and SAML POST.
                .doesNotContain("form-action");
    }

    @Test
    @DisplayName("A page rendering during the request and the header agree on one nonce")
    void nonce_is_stable_within_a_request() {
        MockHttpServletRequest req = new MockHttpServletRequest("GET", "/x");
        String rendered = ContentSecurityPolicy.nonce(req);
        MockHttpServletResponse res = new MockHttpServletResponse();

        csp.writeHeaders(req, res);

        assertThat(ContentSecurityPolicy.nonce(req)).isEqualTo(rendered);
        assertThat(res.getHeader(ContentSecurityPolicy.HEADER)).contains("'nonce-" + rendered + "'");
    }

    @Test
    @DisplayName("Two requests never share a nonce")
    void nonce_is_per_request() {
        assertThat(ContentSecurityPolicy.nonce(new MockHttpServletRequest()))
                .isNotEqualTo(ContentSecurityPolicy.nonce(new MockHttpServletRequest()));
    }

    @Test
    @DisplayName("A policy already set on the response is not overwritten")
    void respects_existing_header() {
        MockHttpServletResponse res = new MockHttpServletResponse();
        res.setHeader(ContentSecurityPolicy.HEADER, "default-src 'none'");

        csp.writeHeaders(new MockHttpServletRequest(), res);

        assertThat(res.getHeader(ContentSecurityPolicy.HEADER)).isEqualTo("default-src 'none'");
    }

    @Test
    @DisplayName("Only Swagger UI is allowed inline styles")
    void swagger_relaxation_is_scoped() {
        assertThat(ContentSecurityPolicy.policy("/swagger-ui/index.html", "n"))
                .contains("style-src 'self' 'unsafe-inline'");
        assertThat(ContentSecurityPolicy.policy("/api/auth/login", "n"))
                .doesNotContain("unsafe-inline");
    }
}
