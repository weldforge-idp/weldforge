package tech.cwvermaak.weldforge.service.oidc;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * A public client that signs in from a browser must register a web origin.
 *
 * <p>Without one, every cross-origin call the browser makes — discovery, JWKS,
 * the PKCE token exchange — is refused by CORS. The browser reports a blocked
 * fetch as a generic network error, so the symptom is a sign-in button that
 * does nothing, with nothing in the logs on either side. KeyCrypt's SPA client
 * was registered that way on 2026-09-20 and was inert for two days.
 *
 * <p>The cases that must keep working matter as much as the one being blocked.
 * RFC 8252 native apps are public clients that legitimately have no origin, and
 * production holds two of them. A rule that rejected every origin-less public
 * client would have refused both.
 */
@DisplayName("Browser clients must register a web origin; native clients must not have to")
class OidcClientWebOriginRequirementTest {

    private static void check(boolean isPublic, List<String> redirectUris, List<String> webOrigins) {
        OidcClientService.requireWebOriginForBrowserClients(isPublic, redirectUris, webOrigins);
    }

    @Nested
    @DisplayName("refused")
    class Refused {

        @Test
        @DisplayName("public + https redirect + no origin — the KeyCrypt case")
        void browser_client_without_origin_is_refused() {
            assertThatThrownBy(() -> check(true,
                    List.of("https://keycrypt.cwvermaak.tech/callback"), List.of()))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("webOrigins is required")
                    // The message must carry the fix, not just the complaint.
                    .hasMessageContaining("https://keycrypt.cwvermaak.tech");
        }

        @Test
        @DisplayName("a null origin list is the same as none")
        void null_origins_is_refused() {
            assertThatThrownBy(() -> check(true,
                    List.of("https://app.example.com/cb"), null))
                    .isInstanceOf(IllegalArgumentException.class);
        }

        @Test
        @DisplayName("a list of blanks is the same as none")
        void blank_origins_is_refused() {
            assertThatThrownBy(() -> check(true,
                    List.of("https://app.example.com/cb"), List.of("", "   ")))
                    .isInstanceOf(IllegalArgumentException.class);
        }

        @Test
        @DisplayName("a non-loopback http redirect still implies a browser")
        void plain_http_non_loopback_is_refused() {
            assertThatThrownBy(() -> check(true,
                    List.of("http://staging.example.com/cb"), List.of()))
                    .isInstanceOf(IllegalArgumentException.class);
        }
    }

    @Nested
    @DisplayName("allowed — these must not regress")
    class Allowed {

        @Test
        @DisplayName("native app on loopback (keycrypt-desktop, live in production)")
        void loopback_native_client_needs_no_origin() {
            assertThatCode(() -> check(true, List.of("http://127.0.0.1/callback"), List.of()))
                    .doesNotThrowAnyException();
            assertThatCode(() -> check(true, List.of("http://localhost:8080/cb"), List.of()))
                    .doesNotThrowAnyException();
            assertThatCode(() -> check(true, List.of("http://[::1]:1234/cb"), List.of()))
                    .doesNotThrowAnyException();
        }

        @Test
        @DisplayName("mobile app on a private-use scheme (leap-mobile, live in production)")
        void private_use_scheme_client_needs_no_origin() {
            assertThatCode(() -> check(true,
                    List.of("online.appiary.leap://oauth/callback"), List.of()))
                    .doesNotThrowAnyException();
        }

        @Test
        @DisplayName("confidential clients are server-side and make no browser calls")
        void confidential_client_needs_no_origin() {
            assertThatCode(() -> check(false,
                    List.of("https://app.example.com/login/oauth2/code/weldforge"), List.of()))
                    .doesNotThrowAnyException();
        }

        @Test
        @DisplayName("a browser client that registers its origin is fine")
        void browser_client_with_origin_is_allowed() {
            assertThatCode(() -> check(true,
                    List.of("https://app.example.com/cb"), List.of("https://app.example.com")))
                    .doesNotThrowAnyException();
        }

        @Test
        @DisplayName("a native redirect alongside a browser one is still required to have an origin")
        void mixed_redirects_follow_the_browser_one() {
            // Desktop plus web in one client: the browser half still needs CORS.
            assertThatThrownBy(() -> check(true,
                    List.of("http://127.0.0.1/cb", "https://app.example.com/cb"), List.of()))
                    .isInstanceOf(IllegalArgumentException.class);
        }
    }
}
