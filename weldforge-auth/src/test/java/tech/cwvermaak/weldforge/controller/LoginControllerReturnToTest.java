package tech.cwvermaak.weldforge.controller;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import tech.cwvermaak.weldforge.config.tenant.PublicHostProperties;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/**
 * Open-redirect rules for the hosted login form's OIDC bounce-back, plus the
 * dev-port regression: a base domain carrying an explicit port
 * ("localhost:8076") used to fail every bounce-back closed to "/", because it
 * was compared against {@code URI.getHost()}, which never carries a port. The
 * visible symptom was a successful sign-in landing on the tenant apex — and
 * therefore on "Missing or invalid x-app-authorization header" — instead of
 * completing the authorization-code flow.
 */
class LoginControllerReturnToTest {

    private LoginController controllerFor(String baseDomain) {
        PublicHostProperties publicHost = new PublicHostProperties();
        publicHost.setBaseDomain(baseDomain);
        return new LoginController(
                mock(tech.cwvermaak.weldforge.service.AuthService.class),
                mock(tech.cwvermaak.weldforge.repository.TenantRepository.class),
                mock(tech.cwvermaak.weldforge.service.PasswordResetService.class),
                publicHost);
    }

    private static String encode(String url) {
        return Base64.getUrlEncoder().withoutPadding()
                .encodeToString(url.getBytes(StandardCharsets.UTF_8));
    }

    @Test
    @DisplayName("apex authorize URL is accepted when the base domain carries a dev port")
    void acceptsApexAuthorizeUrlOnPortedBaseDomain() {
        String url = "http://localhost:8076/t/wellspring/oauth2/authorize?client_id=x";
        assertThat(controllerFor("localhost:8076").sanitiseReturnTo(encode(url)))
                .isEqualTo(url);
    }

    @Test
    @DisplayName("apex authorize URL is accepted on a portless base domain")
    void acceptsApexAuthorizeUrlOnPortlessBaseDomain() {
        String url = "https://sso.weldforge.org/t/acme/oauth2/authorize?client_id=x";
        assertThat(controllerFor("sso.weldforge.org").sanitiseReturnTo(encode(url)))
                .isEqualTo(url);
    }

    @Test
    @DisplayName("a mismatched port is rejected even when the host matches")
    void rejectsMismatchedPort() {
        String url = "http://localhost:9999/t/wellspring/oauth2/authorize";
        assertThat(controllerFor("localhost:8076").sanitiseReturnTo(encode(url)))
                .isEqualTo("/");
    }

    @Test
    @DisplayName("a tenant subdomain is rejected — bounce-back is apex-only")
    void rejectsTenantSubdomain() {
        String url = "http://wellspring.localhost:8076/t/wellspring/oauth2/authorize";
        assertThat(controllerFor("localhost:8076").sanitiseReturnTo(encode(url)))
                .isEqualTo("/");
    }

    @Test
    @DisplayName("an off-domain host is rejected")
    void rejectsForeignHost() {
        String url = "https://evil.example.com/t/acme/oauth2/authorize";
        assertThat(controllerFor("sso.weldforge.org").sanitiseReturnTo(encode(url)))
                .isEqualTo("/");
    }

    @Test
    @DisplayName("an absolute URL outside /t/ is rejected")
    void rejectsNonTenantPath() {
        String url = "http://localhost:8076/admin";
        assertThat(controllerFor("localhost:8076").sanitiseReturnTo(encode(url)))
                .isEqualTo("/");
    }

    @Test
    @DisplayName("blank and malformed input fall back to /")
    void fallsBackForBlankAndMalformed() {
        LoginController c = controllerFor("localhost:8076");
        assertThat(c.sanitiseReturnTo(null)).isEqualTo("/");
        assertThat(c.sanitiseReturnTo("")).isEqualTo("/");
        assertThat(c.sanitiseReturnTo("!!!not-base64!!!")).isEqualTo("/");
    }

    @Test
    @DisplayName("a relative path is preserved; a scheme-relative one is not")
    void handlesRelativeTargets() {
        LoginController c = controllerFor("localhost:8076");
        assertThat(c.sanitiseReturnTo(encode("/t/wellspring/oauth2/authorize")))
                .isEqualTo("/t/wellspring/oauth2/authorize");
        assertThat(c.sanitiseReturnTo(encode("evil.example.com/steal"))).isEqualTo("/");
    }
}
