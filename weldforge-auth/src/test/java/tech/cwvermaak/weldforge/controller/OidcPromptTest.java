package tech.cwvermaak.weldforge.controller;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * {@code prompt} is a SPACE-DELIMITED LIST (OIDC Core §3.1.2.1), not a token.
 *
 * <p>It was compared with {@code "none".equals(prompt)}, which is correct for
 * a single value and silently wrong for every combination: {@code prompt=
 * "consent none"} matched neither branch, so a relying party asking for two
 * things got neither — and a 200.
 */
@DisplayName("The prompt parameter")
class OidcPromptTest {

    @Test
    @DisplayName("absent or blank asks for nothing")
    void empty() {
        assertThat(OidcPrompt.parse(null).isEmpty()).isTrue();
        assertThat(OidcPrompt.parse("").isEmpty()).isTrue();
        assertThat(OidcPrompt.parse("   ").isEmpty()).isTrue();
    }

    @Test
    @DisplayName("a single value is recognised")
    void single() {
        assertThat(OidcPrompt.parse("none").has(OidcPrompt.NONE)).isTrue();
        assertThat(OidcPrompt.parse("login").has(OidcPrompt.LOGIN)).isTrue();
        assertThat(OidcPrompt.parse("consent").has(OidcPrompt.CONSENT)).isTrue();
    }

    @Test
    @DisplayName("several values are all recognised — the case that used to match nothing")
    void several() {
        OidcPrompt p = OidcPrompt.parse("login consent");
        assertThat(p.has(OidcPrompt.LOGIN)).isTrue();
        assertThat(p.has(OidcPrompt.CONSENT)).isTrue();
        assertThat(p.has(OidcPrompt.NONE)).isFalse();
    }

    @Test
    @DisplayName("irregular whitespace does not hide a value")
    void whitespace() {
        OidcPrompt p = OidcPrompt.parse("  login   consent  ");
        assertThat(p.has(OidcPrompt.LOGIN)).isTrue();
        assertThat(p.has(OidcPrompt.CONSENT)).isTrue();
    }

    @Test
    @DisplayName("values are case-sensitive, as the spec defines them")
    void caseSensitive() {
        // "Login" is not a defined value; treating it as one would accept a
        // request we do not in fact honour.
        assertThat(OidcPrompt.parse("Login").has(OidcPrompt.LOGIN)).isFalse();
    }

    @Test
    @DisplayName("none combined with anything else is a contradiction")
    void noneWithOthers() {
        assertThat(OidcPrompt.parse("none login").noneCombinedWithOthers()).isTrue();
        assertThat(OidcPrompt.parse("none consent").noneCombinedWithOthers()).isTrue();
        assertThat(OidcPrompt.parse("none").noneCombinedWithOthers()).isFalse();
        assertThat(OidcPrompt.parse("login consent").noneCombinedWithOthers()).isFalse();
    }

    @Test
    @DisplayName("login and select_account both demand a fresh authentication")
    void reauthentication() {
        assertThat(OidcPrompt.parse("login").requiresReauthentication()).isTrue();
        assertThat(OidcPrompt.parse("select_account").requiresReauthentication()).isTrue();
        // consent re-asks the consent question, not the identity question.
        assertThat(OidcPrompt.parse("consent").requiresReauthentication()).isFalse();
        assertThat(OidcPrompt.parse("none").requiresReauthentication()).isFalse();
        assertThat(OidcPrompt.parse(null).requiresReauthentication()).isFalse();
    }

    @Test
    @DisplayName("an unrecognised value is carried but demands nothing")
    void unknownValue() {
        OidcPrompt p = OidcPrompt.parse("wibble");
        assertThat(p.requiresReauthentication()).isFalse();
        assertThat(p.has(OidcPrompt.NONE)).isFalse();
        assertThat(p.isEmpty()).isFalse();
    }
}
