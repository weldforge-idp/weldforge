package tech.cwvermaak.weldforge.controller;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import tech.cwvermaak.weldforge.model.OidcClient;
import tech.cwvermaak.weldforge.model.User;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Everything the consent screen has to hand back to {@code /decide}.
 *
 * <p>The consent form is a full round trip through the browser: the
 * authorization request is dismantled into hidden inputs and reassembled from
 * the POST, so a parameter that is not rendered here is silently gone by the
 * time the code is issued. Nothing else in the suite looked at these fields,
 * which is why {@code max_age} could be — and once was — dropped without a
 * single test noticing.
 *
 * <p>Each assertion below is a parameter whose loss is invisible at the time
 * and expensive later: the request succeeds, a token comes back, and it is
 * quietly the wrong token.
 */
class ConsentFormRoundTripTest {

    private static final String RESOURCE = "https://shot.cwvermaak.tech/mcp/counteract-studios";

    private String consent(Integer maxAge, String resource) {
        return consent(maxAge, resource, Map.of());
    }

    private String consent(Integer maxAge, String resource, Map<String, String> words) {
        return OidcAuthorizationController.renderConsent("acme",
                User.builder().email("alice@acme.test").build(),
                OidcClient.builder().clientId("wf_client_1").name("Acme App").build(),
                "https://app.acme.test/cb", "openid email", words, "st", "no",
                "challenge", "S256", maxAge, resource, "csrf-token", "nonce-1");
    }

    /** A hidden input with this name and value, however the attributes are ordered. */
    private static boolean hasHidden(String html, String name, String value) {
        return html.contains("name=\"" + name + "\" value=\"" + value + "\"");
    }

    @Test
    @DisplayName("the resource survives the consent round trip")
    void resource_is_carried() {
        // Dropped here, the token comes back audienced to the client instead
        // of the resource, the resource server refuses it, and nothing on
        // either side says the consent screen was where it was lost.
        assertThat(hasHidden(consent(null, RESOURCE), "resource", RESOURCE))
                .as("the consent form must post the resource back to /decide")
                .isTrue();
    }

    @Test
    @DisplayName("max_age survives the consent round trip")
    void max_age_is_carried() {
        assertThat(hasHidden(consent(300, null), "max_age", "300"))
                .as("the freshness the relying party asked for must not be lost at consent")
                .isTrue();
    }

    @Test
    @DisplayName("the PKCE challenge and its method survive the consent round trip")
    void pkce_is_carried() {
        String html = consent(null, null);

        assertThat(hasHidden(html, "code_challenge", "challenge")).isTrue();
        assertThat(hasHidden(html, "code_challenge_method", "S256")).isTrue();
    }

    @Test
    @DisplayName("an absent parameter is posted back empty, not omitted")
    void absent_parameters_round_trip_as_empty() {
        String html = consent(null, null);

        // /decide reads these with blankToNull, so an empty value is how
        // "there wasn't one" is expressed. Omitting the input entirely would
        // work too, but the two must not disagree: the point of asserting it
        // is that the form's shape is stable whichever way round it is.
        assertThat(hasHidden(html, "resource", "")).isTrue();
        assertThat(hasHidden(html, "max_age", "")).isTrue();
    }

    @Test
    @DisplayName("a resource with HTML-significant characters is escaped, not injected")
    void resource_is_escaped() {
        String nasty = "https://evil.test/\"><script>alert(1)</script>";

        String html = consent(null, nasty);

        assertThat(html)
                .as("the resource is attacker-supplied and reaches the page as an attribute")
                .doesNotContain("<script>alert(1)</script>");
    }

    @Test
    @DisplayName("a described scope is shown in words, with its name still beside it")
    void described_scope_shows_words_and_name() {
        String html = consent(null, null, Map.of("email", "See the address you signed up with"));

        assertThat(html)
                .as("the words are the whole reason the registry exists")
                .contains("See the address you signed up with");
        assertThat(html)
                .as("the name stays visible so a developer can still tell which scope it is")
                .contains("<span class=\"scope-name\">email</span>");
    }

    @Test
    @DisplayName("an undescribed scope renders exactly as it did before the registry")
    void undescribed_scope_is_unchanged() {
        // The tenant described one of the two requested scopes. The other has
        // to keep working, or registering a description for one scope would
        // quietly change how every other scope is presented.
        String html = consent(null, null, Map.of("email", "See your address"));

        assertThat(html).contains("<li>openid</li>");
    }

    @Test
    @DisplayName("a description is escaped, not injected")
    void description_is_escaped() {
        // Descriptions are tenant-supplied and land in the page unquoted, so
        // this is the one spot where a tenant admin could script the consent
        // screen their own users are reading.
        String html = consent(null, null,
                Map.of("email", "<script>alert(1)</script>"));

        assertThat(html).doesNotContain("<script>alert(1)</script>");
    }
}
