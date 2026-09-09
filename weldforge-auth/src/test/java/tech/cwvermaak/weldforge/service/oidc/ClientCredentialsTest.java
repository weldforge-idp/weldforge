package tech.cwvermaak.weldforge.service.oidc;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * CONF-4.1 — RFC 6749 §2.3.1 client authentication.
 *
 * <p>The server accepted only form-body credentials, so a client library
 * configured the conformant way — which for most libraries is the default —
 * could not authenticate. Discovery was honest about that, but dynamic
 * registration then handed new clients {@code client_secret_basic} as their
 * method, which the server could not parse. Three components disagreed about
 * one contract.
 */
class ClientCredentialsTest {

    private static MockHttpServletRequest withBasic(String raw) {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/t/leap/oauth2/token");
        request.addHeader("Authorization", "Basic "
                + Base64.getEncoder().encodeToString(raw.getBytes(StandardCharsets.UTF_8)));
        return request;
    }

    @Test
    @DisplayName("HTTP Basic credentials are accepted")
    void basic_is_accepted() {
        var creds = ClientCredentials.resolve(withBasic("portal:s3cret"), null, null);

        assertThat(creds.clientId()).isEqualTo("portal");
        assertThat(creds.clientSecret()).isEqualTo("s3cret");
    }

    @Test
    @DisplayName("Form credentials still work, so existing clients are unaffected")
    void form_still_works() {
        var creds = ClientCredentials.resolve(
                new MockHttpServletRequest("POST", "/t/leap/oauth2/token"), "portal", "s3cret");

        assertThat(creds.clientId()).isEqualTo("portal");
        assertThat(creds.clientSecret()).isEqualTo("s3cret");
    }

    @Test
    @DisplayName("A secret may contain a colon — the FIRST colon separates")
    void secret_may_contain_a_colon() {
        var creds = ClientCredentials.resolve(withBasic("portal:a:b:c"), null, null);

        assertThat(creds.clientId()).isEqualTo("portal");
        assertThat(creds.clientSecret()).isEqualTo("a:b:c");
    }

    @Test
    @DisplayName("Percent-encoded credentials are decoded, per §2.3.1")
    void percent_encoding_is_reversed() {
        // §2.3.1 requires each half to be form-urlencoded before base64. Most
        // clients never exercise it, which is exactly why it is easy to get
        // wrong: a secret containing a space or a plus would silently mismatch.
        var creds = ClientCredentials.resolve(withBasic("my%20client:p%40ss%2Bword"), null, null);

        assertThat(creds.clientId()).isEqualTo("my client");
        assertThat(creds.clientSecret()).isEqualTo("p@ss+word");
    }

    @Test
    @DisplayName("Using both methods at once is refused, not silently resolved")
    void both_methods_is_refused() {
        // §2.3.1: "The client MUST NOT use more than one authentication method
        // in each request." Preferring one silently would let a caller smuggle
        // a second identity past whichever layer read the other.
        assertThatThrownBy(() -> ClientCredentials.resolve(withBasic("portal:s3cret"), "portal", "other"))
                .isInstanceOf(OidcAuthorizationException.class)
                .hasMessageContaining("not both");
    }

    @Test
    @DisplayName("A bare client_id alongside Basic is allowed when it agrees")
    void echoed_client_id_is_tolerated() {
        // Clients routinely echo client_id for logging. Rejecting that would
        // break working integrations for no gain -- Basic is what authenticates.
        var creds = ClientCredentials.resolve(withBasic("portal:s3cret"), "portal", null);

        assertThat(creds.clientId()).isEqualTo("portal");
    }

    @Test
    @DisplayName("A conflicting client_id alongside Basic is refused")
    void conflicting_client_id_is_refused() {
        assertThatThrownBy(() -> ClientCredentials.resolve(withBasic("portal:s3cret"), "other", null))
                .isInstanceOf(OidcAuthorizationException.class)
                .hasMessageContaining("does not match");
    }

    @Test
    @DisplayName("Malformed Basic is refused rather than falling through to the form")
    void malformed_basic_is_refused() {
        MockHttpServletRequest notBase64 = new MockHttpServletRequest("POST", "/t/leap/oauth2/token");
        notBase64.addHeader("Authorization", "Basic !!!not-base64!!!");

        // Falling back to form parameters here would turn a client bug into a
        // confusing 401 somewhere else. The caller meant to authenticate.
        assertThatThrownBy(() -> ClientCredentials.resolve(notBase64, "portal", "s3cret"))
                .isInstanceOf(OidcAuthorizationException.class);
    }

    @Test
    @DisplayName("Basic with no colon is malformed")
    void basic_without_colon_is_refused() {
        assertThatThrownBy(() -> ClientCredentials.resolve(withBasic("portal-no-secret"), null, null))
                .isInstanceOf(OidcAuthorizationException.class);
    }

    @Test
    @DisplayName("An empty secret resolves to null, so a public client authenticates by id")
    void empty_secret_is_null() {
        var creds = ClientCredentials.resolve(withBasic("public-app:"), null, null);

        assertThat(creds.clientId()).isEqualTo("public-app");
        assertThat(creds.clientSecret()).isNull();
    }

    @Test
    @DisplayName("A non-Basic Authorization header is ignored, not misread")
    void bearer_header_is_ignored() {
        MockHttpServletRequest bearer = new MockHttpServletRequest("POST", "/t/leap/oauth2/token");
        bearer.addHeader("Authorization", "Bearer some-token");

        var creds = ClientCredentials.resolve(bearer, "portal", "s3cret");

        assertThat(creds.clientId()).isEqualTo("portal");
        assertThat(creds.clientSecret()).isEqualTo("s3cret");
    }
}
