package tech.cwvermaak.weldforge.config.security;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * WF-14 — the rate limiter matches its routes on the decoded, normalised path,
 * so a percent-encoded path, a trailing slash or matrix parameters cannot slip
 * a throttled endpoint past the limiter (it used to key on the raw
 * {@code getRequestURI()}, which Tomcat decodes before routing).
 */
class RateLimitingFilterPathTest {

    /** Tomcat exposes the decoded, normalised path through getServletPath(). */
    private static MockHttpServletRequest req(String servletPath, String requestUri) {
        MockHttpServletRequest r = new MockHttpServletRequest("POST", requestUri);
        r.setServletPath(servletPath);
        return r;
    }

    @Test
    @DisplayName("a plain path is returned unchanged")
    void plainPath() {
        assertThat(RateLimitingFilter.matchPath(req("/api/auth/login", "/api/auth/login")))
                .isEqualTo("/api/auth/login");
    }

    @Test
    @DisplayName("a percent-encoded path resolves to the decoded route, not the raw URI")
    void percentEncoded() {
        // Tomcat decodes %67 -> 'g' for the servlet path and routes to login;
        // the raw URI still carries the encoding. The limiter must follow the
        // decoded path, or the bucket is missed.
        assertThat(RateLimitingFilter.matchPath(req("/api/auth/login", "/api/auth/lo%67in")))
                .isEqualTo("/api/auth/login");
    }

    @Test
    @DisplayName("a trailing slash maps to the same route")
    void trailingSlash() {
        assertThat(RateLimitingFilter.matchPath(req("/api/auth/login/", "/api/auth/login/")))
                .isEqualTo("/api/auth/login");
    }

    @Test
    @DisplayName("matrix parameters are dropped")
    void matrixParams() {
        assertThat(RateLimitingFilter.matchPath(req("/api/auth/login;jsessionid=abc", "/api/auth/login;jsessionid=abc")))
                .isEqualTo("/api/auth/login");
    }

    @Test
    @DisplayName("with no servlet path, the raw URI is decoded through URI before matching")
    void fallbackDecodesRawUri() {
        assertThat(RateLimitingFilter.matchPath(req("", "/api/auth/lo%67in")))
                .isEqualTo("/api/auth/login");
    }

    @Test
    @DisplayName("an unrelated path is left as-is (and will not match any throttled route)")
    void unrelatedPath() {
        assertThat(RateLimitingFilter.matchPath(req("/api/admin/users", "/api/admin/users")))
                .isEqualTo("/api/admin/users");
    }
}
