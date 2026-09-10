package tech.cwvermaak.weldforge.controller;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import tech.cwvermaak.weldforge.config.security.ContentSecurityPolicy;
import tech.cwvermaak.weldforge.model.OidcClient;
import tech.cwvermaak.weldforge.model.User;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * CONF-7.2, "the consent page renders under its own policy": every inline
 * block on a server-rendered page carries the nonce the response's CSP header
 * names, and nothing on the page needs what the policy forbids (inline event
 * handlers, style attributes).
 */
class ServerRenderedPagesCspTest {

    /** Nonce the header would carry for this request. */
    private static String headerNonce(MockHttpServletRequest req) {
        MockHttpServletResponse res = new MockHttpServletResponse();
        new ContentSecurityPolicy().writeHeaders(req, res);
        Matcher m = Pattern.compile("'nonce-([^']+)'").matcher(res.getHeader(ContentSecurityPolicy.HEADER));
        assertThat(m.find()).isTrue();
        return m.group(1);
    }

    private static void assertEveryInlineBlockCarries(String html, String nonce) {
        Matcher blocks = Pattern.compile("<(style|script)([^>]*)>").matcher(html);
        int seen = 0;
        while (blocks.find()) {
            seen++;
            assertThat(blocks.group(2)).as("<%s> must carry the response nonce", blocks.group(1))
                    .contains("nonce=\"" + nonce + "\"");
        }
        assertThat(seen).as("page has inline blocks to check").isPositive();
        // Nonces cannot be attached to these, so the policy simply blocks them.
        assertThat(html).doesNotContainPattern("\\son[a-z]+\\s*=");
        assertThat(html).doesNotContainPattern("\\sstyle\\s*=");
    }

    @Test
    @DisplayName("The consent page's stylesheet carries the nonce its CSP names")
    void consent_page() {
        MockHttpServletRequest req = new MockHttpServletRequest("GET", "/t/acme/oauth2/authorize");
        String nonce = ContentSecurityPolicy.nonce(req);

        String html = OidcAuthorizationController.renderConsent("acme",
                User.builder().email("alice@acme.test").build(),
                OidcClient.builder().clientId("wf_client_1").name("Acme App").build(),
                "https://app.acme.test/cb", "openid email", "st", "no", null, null, null,
                "csrf-token", nonce);

        assertThat(headerNonce(req)).isEqualTo(nonce);
        assertEveryInlineBlockCarries(html, nonce);
        assertThat(html).contains("Acme App wants to access your account");
    }

    @Test
    @DisplayName("The SAML POST form submits from a nonce'd script, not an onload handler")
    void saml_auto_submit_form() {
        MockHttpServletRequest req = new MockHttpServletRequest("POST", "/t/acme/saml2/idp/sso");
        String nonce = ContentSecurityPolicy.nonce(req);

        String html = SamlIdpController.buildAutoSubmitForm(
                "https://sp.acme.test/acs", "UkVTUE9OU0U=", "relay", nonce);

        assertThat(headerNonce(req)).isEqualTo(nonce);
        assertEveryInlineBlockCarries(html, nonce);
        assertThat(html).contains("document.forms[0].submit()").contains("<noscript>");
    }

    @Test
    @DisplayName("The tenant verification page renders, with both blocks nonce'd")
    void verify_contact_page() {
        MockHttpServletRequest req = new MockHttpServletRequest("GET", "/api/auth/tenants/verify-contact-page");
        String nonce = ContentSecurityPolicy.nonce(req);

        // Regression: a bare "100%" in the CSS made String.formatted throw, and
        // every emailed verification link answered 400 "Conversion = ';'".
        String html = AuthController.verifyContactHtml("tok-123", nonce);

        assertThat(headerNonce(req)).isEqualTo(nonce);
        assertEveryInlineBlockCarries(html, nonce);
        assertThat(html).contains("width: 100%;").contains("const token = \"tok-123\";");
    }
}
