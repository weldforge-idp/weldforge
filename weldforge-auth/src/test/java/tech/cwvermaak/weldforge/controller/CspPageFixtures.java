package tech.cwvermaak.weldforge.controller;

import tech.cwvermaak.weldforge.config.tenant.PublicHostProperties;
import tech.cwvermaak.weldforge.model.OidcClient;
import tech.cwvermaak.weldforge.model.User;
import tech.cwvermaak.weldforge.repository.TenantRepository;
import tech.cwvermaak.weldforge.service.AuthService;
import tech.cwvermaak.weldforge.service.PasswordResetService;
import tech.cwvermaak.weldforge.service.security.PasswordPolicyProperties;

import static org.mockito.Mockito.mock;

/**
 * The real server-rendered pages, for tests outside this package (the BDD
 * steps). The renderers are package-private on purpose; this is the one
 * doorway to them.
 */
public final class CspPageFixtures {

    private CspPageFixtures() {}

    public static String consentPage(String cspNonce) {
        return OidcAuthorizationController.renderConsent("acme",
                User.builder().email("alice@acme.test").build(),
                OidcClient.builder().clientId("wf_client_1").name("Acme App").build(),
                "https://app.acme.test/cb", "openid email", "st", "no", null, null, null,
                "csrf-token", cspNonce);
    }

    public static String samlPostForm(String cspNonce) {
        return SamlIdpController.buildAutoSubmitForm(
                "https://sp.acme.test/acs", "UkVTUE9OU0U=", "relay", cspNonce);
    }

    public static String verifyContactPage(String cspNonce) {
        return AuthController.verifyContactHtml("tok-123", cspNonce);
    }

    /** Reads its nonce from the current request context, as in production. */
    public static String hostedSignInPage() {
        return new LoginController(mock(AuthService.class), mock(TenantRepository.class),
                mock(PasswordResetService.class), new PublicHostProperties(),
                new PasswordPolicyProperties()).form(null, null).getBody();
    }
}
