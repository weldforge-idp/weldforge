package tech.cwvermaak.weldforge.config.security;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.InsufficientAuthenticationException;

import static org.assertj.core.api.Assertions.assertThat;

/** CONF-7.3: an unauthenticated /api/** call is a 401 problem document, not a redirect to /login. */
class ApiAuthenticationEntryPointTest {

    @Test
    @DisplayName("401 problem+json carrying the standard and the legacy members")
    void unauthenticated_is_a_problem() throws Exception {
        MockHttpServletResponse res = new MockHttpServletResponse();

        new ApiAuthenticationEntryPoint().commence(
                new MockHttpServletRequest("GET", "/api/admin/tenants"), res,
                new InsufficientAuthenticationException("no token"));

        assertThat(res.getStatus()).isEqualTo(401);
        assertThat(res.getContentType()).startsWith("application/problem+json");
        assertThat(res.getRedirectedUrl()).isNull();
        assertThat(res.getContentAsString())
                .contains("\"type\":\"tag:weldforge.org,2026:problem:unauthorized\"")
                .contains("\"status\":401")
                .contains("\"detail\":\"Authentication required\"")
                .contains("\"error\":\"unauthorized\"")
                // The exception's own text is not echoed back.
                .doesNotContain("no token");
    }
}
