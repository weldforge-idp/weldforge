package tech.cwvermaak.weldforge.service;

import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * B-TEN-7: which refresh cookie a request's refresh uses, and whether the
 * legacy cookie follows the rotation.
 */
class AuthServiceRefreshCookieTest {

    private static AuthService.PresentedRefresh read(String slug, Cookie... cookies) {
        MockHttpServletRequest req = new MockHttpServletRequest("POST", "/api/auth/refresh");
        if (cookies.length > 0) req.setCookies(cookies);
        return AuthService.readRefreshCookie(req, slug);
    }

    @Test
    @DisplayName("cookie names are per tenant and distinct from the legacy name")
    void names() {
        assertThat(AuthService.refreshCookieName("cwvermaak-tech")).isEqualTo("wf_refresh_cwvermaak-tech");
        assertThat(AuthService.refreshCookieName("default")).isNotEqualTo(AuthService.REFRESH_COOKIE);
        // Safe Space matches on the exact prefix "refresh_token="; ours must not start with it.
        assertThat(AuthService.refreshCookieName("x")).doesNotStartWith(AuthService.REFRESH_COOKIE);
    }

    @Test
    @DisplayName("the tenant's own cookie wins over the legacy one")
    void own_cookie_first() {
        var p = read("default", new Cookie("refresh_token", "bob-token"), new Cookie("wf_refresh_default", "alice-token"));
        assertThat(p.rawToken()).isEqualTo("alice-token");
        assertThat(p.rewriteLegacy()).as("the legacy cookie is another session's").isFalse();
    }

    @Test
    @DisplayName("a legacy cookie holding the same token follows the rotation")
    void same_session_legacy_follows() {
        var p = read("default", new Cookie("wf_refresh_default", "t1"), new Cookie("refresh_token", "t1"));
        assertThat(p.rawToken()).isEqualTo("t1");
        assertThat(p.rewriteLegacy()).isTrue();
    }

    @Test
    @DisplayName("another tenant's cookie is never used")
    void other_tenants_cookie_ignored() {
        var p = read("default", new Cookie("wf_refresh_intellisuite", "bob-token"));
        assertThat(p.rawToken()).isNull();
    }

    @Test
    @DisplayName("legacy only (a server-side proxy): used, and rewritten")
    void legacy_only() {
        var p = read("techmetropolis", new Cookie("refresh_token", "proxy-token"));
        assertThat(p.rawToken()).isEqualTo("proxy-token");
        assertThat(p.rewriteLegacy()).isTrue();
    }

    @Test
    @DisplayName("no cookies, or a blank per-tenant cookie, falls through cleanly")
    void nothing() {
        assertThat(read("default").rawToken()).isNull();
        var p = read("default", new Cookie("wf_refresh_default", ""), new Cookie("refresh_token", "legacy"));
        assertThat(p.rawToken()).isEqualTo("legacy");
    }
}
