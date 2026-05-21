package tech.cwvermaak.weldforge.config;

import jakarta.servlet.FilterChain;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

/**
 * The Content-Type guard converts the implicit "JSON-only" invariant on
 * {@code /api/auth/**} into a hard 415. Closes the form-CSRF surface
 * that the parent-domain-scoped session cookie would otherwise expose.
 */
class AuthJsonContentTypeFilterTest {

    private final AuthJsonContentTypeFilter filter = new AuthJsonContentTypeFilter();

    @Test
    @DisplayName("POST /api/auth/login with application/json is allowed through")
    void json_allowed() throws Exception {
        MockHttpServletRequest req = new MockHttpServletRequest("POST", "/api/auth/login");
        req.setContent("{\"identifier\":\"u\",\"password\":\"p\"}".getBytes());
        req.setContentType("application/json");
        MockHttpServletResponse res = new MockHttpServletResponse();
        FilterChain chain = mock(FilterChain.class);

        filter.doFilter(req, res, chain);

        verify(chain, times(1)).doFilter(req, res);
        assertThat(res.getStatus()).isEqualTo(200);
    }

    @Test
    @DisplayName("POST /api/auth/login with application/json; charset=UTF-8 is allowed (parameter stripped)")
    void json_with_charset_allowed() throws Exception {
        MockHttpServletRequest req = new MockHttpServletRequest("POST", "/api/auth/login");
        req.setContent("{}".getBytes());
        req.setContentType("application/json; charset=UTF-8");
        MockHttpServletResponse res = new MockHttpServletResponse();
        FilterChain chain = mock(FilterChain.class);

        filter.doFilter(req, res, chain);

        verify(chain, times(1)).doFilter(req, res);
    }

    @Test
    @DisplayName("POST /api/auth/login with form-encoded body is refused 415")
    void form_encoded_refused() throws Exception {
        MockHttpServletRequest req = new MockHttpServletRequest("POST", "/api/auth/login");
        req.setContent("identifier=u&password=p".getBytes());
        req.setContentType("application/x-www-form-urlencoded");
        MockHttpServletResponse res = new MockHttpServletResponse();
        FilterChain chain = mock(FilterChain.class);

        filter.doFilter(req, res, chain);

        verify(chain, never()).doFilter(req, res);
        assertThat(res.getStatus()).isEqualTo(415);
        assertThat(res.getContentAsString()).contains("unsupported_media_type");
    }

    @Test
    @DisplayName("POST /api/auth/login with text/plain (no preflight needed) is refused 415")
    void text_plain_refused() throws Exception {
        MockHttpServletRequest req = new MockHttpServletRequest("POST", "/api/auth/login");
        req.setContent("anything".getBytes());
        req.setContentType("text/plain");
        MockHttpServletResponse res = new MockHttpServletResponse();
        FilterChain chain = mock(FilterChain.class);

        filter.doFilter(req, res, chain);

        verify(chain, never()).doFilter(req, res);
        assertThat(res.getStatus()).isEqualTo(415);
    }

    @Test
    @DisplayName("POST /api/auth/login with multipart/form-data is refused 415")
    void multipart_refused() throws Exception {
        MockHttpServletRequest req = new MockHttpServletRequest("POST", "/api/auth/login");
        req.setContent("--boundary\r\n".getBytes());
        req.setContentType("multipart/form-data; boundary=boundary");
        MockHttpServletResponse res = new MockHttpServletResponse();
        FilterChain chain = mock(FilterChain.class);

        filter.doFilter(req, res, chain);

        verify(chain, never()).doFilter(req, res);
        assertThat(res.getStatus()).isEqualTo(415);
    }

    @Test
    @DisplayName("GET /api/auth/me is allowed regardless of Content-Type (not a mutating method)")
    void get_unrestricted() throws Exception {
        MockHttpServletRequest req = new MockHttpServletRequest("GET", "/api/auth/me");
        req.setContentType("text/plain");
        MockHttpServletResponse res = new MockHttpServletResponse();
        FilterChain chain = mock(FilterChain.class);

        filter.doFilter(req, res, chain);

        verify(chain, times(1)).doFilter(req, res);
    }

    @Test
    @DisplayName("POST /login/forgot (hosted auth form) is NOT under /api/auth/* — form-encoded is allowed")
    void hosted_login_form_unaffected() throws Exception {
        MockHttpServletRequest req = new MockHttpServletRequest("POST", "/login/forgot");
        req.setContent("identifier=u@x".getBytes());
        req.setContentType("application/x-www-form-urlencoded");
        MockHttpServletResponse res = new MockHttpServletResponse();
        FilterChain chain = mock(FilterChain.class);

        filter.doFilter(req, res, chain);

        verify(chain, times(1)).doFilter(req, res);
    }

    @Test
    @DisplayName("DELETE /api/auth/sessions with empty body is allowed (no Content-Type required)")
    void delete_empty_body_allowed() throws Exception {
        MockHttpServletRequest req = new MockHttpServletRequest("DELETE", "/api/auth/sessions");
        // Empty body, no content type set
        MockHttpServletResponse res = new MockHttpServletResponse();
        FilterChain chain = mock(FilterChain.class);

        filter.doFilter(req, res, chain);

        verify(chain, times(1)).doFilter(req, res);
    }

    @Test
    @DisplayName("POST /api/auth/login with NO Content-Type and a body is refused 415")
    void missing_content_type_refused() throws Exception {
        MockHttpServletRequest req = new MockHttpServletRequest("POST", "/api/auth/login");
        req.setContent("{}".getBytes());
        // No setContentType — null
        MockHttpServletResponse res = new MockHttpServletResponse();
        FilterChain chain = mock(FilterChain.class);

        filter.doFilter(req, res, chain);

        verify(chain, never()).doFilter(req, res);
        assertThat(res.getStatus()).isEqualTo(415);
    }
}
