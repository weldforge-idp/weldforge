package tech.cwvermaak.weldforge.controller;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The consent screen replays every authorization parameter as a hidden field,
 * and a null renders as {@code value=""}. Submitting the form therefore posts
 * {@code code_challenge=}, which Spring binds to an empty String rather than
 * null — so a request that carried no PKCE challenge acquired one in transit.
 *
 * <p>The token endpoint's check is {@code if (codeChallenge != null)}, so it
 * then demanded a {@code code_verifier} the client never had and answered
 * {@code 400 invalid_grant}. <strong>The authorization code was unredeemable
 * from the moment it was issued.</strong>
 *
 * <p>Found by the OpenID conformance suite on 2026-09-20, not by this repo's
 * own tests, because every one of them calls the service directly and so never
 * saw a form round trip. It reproduced on any client without
 * {@code require_pkce}, on every consent screen — and consent re-prompts
 * whenever the requested scopes widen, so it was not a first-login-only case.
 */
@DisplayName("Empty form parameters mean absent, not present-and-empty")
class OidcAuthorizationControllerBlankParamTest {

    @Test
    @DisplayName("an empty string becomes null — the defect itself")
    void empty_becomes_null() {
        assertThat(OidcAuthorizationController.blankToNull(""))
                .as("this exact value is what the consent form posts back")
                .isNull();
    }

    @Test
    @DisplayName("whitespace-only becomes null too")
    void whitespace_becomes_null() {
        assertThat(OidcAuthorizationController.blankToNull("   ")).isNull();
        assertThat(OidcAuthorizationController.blankToNull("\t")).isNull();
    }

    @Test
    @DisplayName("null stays null")
    void null_stays_null() {
        assertThat(OidcAuthorizationController.blankToNull(null)).isNull();
    }

    @Test
    @DisplayName("a real PKCE challenge is passed through untouched")
    void real_value_survives() {
        // The direction that matters second-most: over-normalising would break
        // PKCE for every client that legitimately uses it, which is all of the
        // production clients that run a browser flow.
        String challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

        assertThat(OidcAuthorizationController.blankToNull(challenge)).isEqualTo(challenge);
        assertThat(OidcAuthorizationController.blankToNull("S256")).isEqualTo("S256");
    }
}
