package tech.cwvermaak.weldforge.controller;

import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.util.ReflectionTestUtils;
import tech.cwvermaak.weldforge.config.tenant.PublicHostProperties;
import tech.cwvermaak.weldforge.model.Tenant;
import tech.cwvermaak.weldforge.model.User;
import tech.cwvermaak.weldforge.repository.OidcClientRepository;
import tech.cwvermaak.weldforge.repository.TenantRepository;
import tech.cwvermaak.weldforge.repository.UserRepository;
import tech.cwvermaak.weldforge.service.AuthService;
import tech.cwvermaak.weldforge.service.JwtService;
import tech.cwvermaak.weldforge.service.audit.AuditService;
import tech.cwvermaak.weldforge.service.oidc.TenantSigningKeyService;

import java.util.Optional;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * CONF-6.4 — RP-initiated logout must end the session, not merely clear cookies.
 *
 * <p>Before this, {@code resolveUserFromCookie} returned {@code Optional.empty()}
 * unconditionally, so a logout with no {@code id_token_hint} resolved no user and
 * {@code logoutAll} never ran. The browser lost its cookies while every
 * outstanding access and refresh token stayed valid — "sign out" on a shared
 * machine did not sign the user out.
 *
 * <p>The interesting assertions here are the negative ones: the session cookie is
 * signed with the same platform HMAC as the MFA-challenge and consent-CSRF
 * tokens, so purpose and tenant have to be checked or logout becomes a way to
 * terminate someone else's session.
 */
class OidcLogoutCookieResolutionTest {

    private static final String SECRET =
            "conf-6-4-test-secret-long-enough-for-hmac-sha-512-signing-key-material";

    private OidcLogoutController controller;
    private UserRepository userRepository;
    private AuthService authService;
    private JwtService jwtService;

    private Tenant leap;
    private User alice;

    @BeforeEach
    void setUp() {
        jwtService = new JwtService();
        ReflectionTestUtils.setField(jwtService, "secret", SECRET);
        ReflectionTestUtils.setField(jwtService, "audience", "weldforge");
        ReflectionTestUtils.setField(jwtService, "accessExpirationMs", 300_000L);
        ReflectionTestUtils.setField(jwtService, "refreshExpirationMs", 604_800_000L);

        leap = new Tenant();
        leap.setId(1L);
        leap.setSlug("leap");

        alice = new User();
        alice.setId(42L);
        alice.setEmail("alice@leap.test");
        alice.setTenant(leap);

        TenantRepository tenantRepository = mock(TenantRepository.class);
        when(tenantRepository.findBySlug("leap")).thenReturn(Optional.of(leap));

        userRepository = mock(UserRepository.class);
        when(userRepository.findByTenant_SlugAndEmailIgnoreCase("leap", "alice@leap.test"))
                .thenReturn(Optional.of(alice));

        authService = mock(AuthService.class);

        PublicHostProperties publicHost = new PublicHostProperties();

        controller = new OidcLogoutController(
                tenantRepository,
                userRepository,
                mock(OidcClientRepository.class),
                mock(TenantSigningKeyService.class),
                authService,
                publicHost,
                mock(AuditService.class),
                jwtService);
    }

    private MockHttpServletResponse logoutWithCookie(String cookieValue) {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/t/leap/oauth2/logout");
        if (cookieValue != null) {
            request.setCookies(new Cookie(OidcLogoutController.SESSION_COOKIE, cookieValue));
        }
        MockHttpServletResponse response = new MockHttpServletResponse();
        controller.logoutGet("leap", null, null, null, null, request, response);
        return response;
    }

    @Test
    @DisplayName("A session cookie with no id_token_hint still revokes the user's tokens")
    void cookie_only_logout_ends_the_session() {
        String session = jwtService.generateAccessToken(
                "alice@leap.test", 1L, "leap", false, 0);

        logoutWithCookie(session);

        verify(authService).logoutAll(alice);
    }

    @Test
    @DisplayName("An MFA-challenge token is not a session — it must not end one")
    void mfa_challenge_token_is_refused() {
        // Signed by the same platform key as the session cookie. Without the
        // purpose check this would terminate the session of a user who is
        // part-way through authenticating.
        String challenge = jwtService.generateMfaChallengeToken(42L, 1L, "leap");

        logoutWithCookie(challenge);

        verify(authService, never()).logoutAll(any());
    }

    @Test
    @DisplayName("A session in another tenant cannot end this tenant's session")
    void cross_tenant_cookie_is_refused() {
        String otherTenant = jwtService.generateAccessToken(
                "alice@leap.test", 99L, "intellisuite", false, 0);

        logoutWithCookie(otherTenant);

        verify(authService, never()).logoutAll(any());
    }

    @Test
    @DisplayName("A forged cookie is ignored, and logout still clears cookies")
    void unsigned_cookie_is_ignored_but_cookies_still_clear() {
        MockHttpServletResponse response = logoutWithCookie("not-a-jwt");

        verify(authService, never()).logoutAll(any());
        // The cookie-clearing half must still happen — an unauthenticated
        // logout is a legitimate call, not an error.
        Cookie cleared = response.getCookie(OidcLogoutController.SESSION_COOKIE);
        org.assertj.core.api.Assertions.assertThat(cleared).isNotNull();
        org.assertj.core.api.Assertions.assertThat(cleared.getMaxAge()).isZero();
    }

    @Test
    @DisplayName("No cookie at all is a no-op, not a failure")
    void no_cookie_is_a_noop() {
        logoutWithCookie(null);

        verify(authService, never()).logoutAll(any());
    }
}
