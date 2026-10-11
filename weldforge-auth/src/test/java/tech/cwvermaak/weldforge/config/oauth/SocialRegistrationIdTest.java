package tech.cwvermaak.weldforge.config.oauth;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import tech.cwvermaak.weldforge.model.SocialProviderType;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The registrationId split, which three classes used to do for themselves and
 * one of them did differently.
 */
class SocialRegistrationIdTest {

    @Test
    @DisplayName("a slug containing a hyphen keeps all of it")
    void hyphenatedSlug() {
        // The production defect, 2026-10-11. Splitting on the FIRST hyphen
        // gave "counteract", the lookup found no user in a tenant of that
        // name, and a successful Google sign-in ended on a 401.
        var parsed = SocialRegistrationId.parse("counteract-studios-google").orElseThrow();
        assertThat(parsed.tenantSlug()).isEqualTo("counteract-studios");
        assertThat(parsed.provider()).isEqualTo(SocialProviderType.GOOGLE);
    }

    @Test
    @DisplayName("slugs in real use, each with a hyphen")
    void realSlugs() {
        assertThat(SocialRegistrationId.parse("cwvermaak-tech-google").orElseThrow().tenantSlug())
                .isEqualTo("cwvermaak-tech");
        assertThat(SocialRegistrationId.parse("hbc-2s-connect-microsoft").orElseThrow().tenantSlug())
                .isEqualTo("hbc-2s-connect");
        assertThat(SocialRegistrationId.parse("leap-github").orElseThrow().tenantSlug())
                .isEqualTo("leap");
    }

    @Test
    @DisplayName("no provider name contains a hyphen, which is what makes the last-hyphen rule safe")
    void noProviderNameContainsAHyphen() {
        // If this ever fails, the split rule is wrong, not this test: a
        // provider like SIGN_IN_WITH_APPLE is fine (underscore), but a
        // hyphenated one would make the id ambiguous.
        for (SocialProviderType p : SocialProviderType.values()) {
            assertThat(p.name()).doesNotContain("-");
        }
    }

    @Test
    @DisplayName("round-trips with the id builder")
    void roundTrip() {
        for (SocialProviderType p : SocialProviderType.values()) {
            String id = SocialRegistrationId.of("counteract-studios", p);
            var parsed = SocialRegistrationId.parse(id).orElseThrow();
            assertThat(parsed.tenantSlug()).isEqualTo("counteract-studios");
            assertThat(parsed.provider()).isEqualTo(p);
            assertThat(id).isEqualTo("counteract-studios-" + p.name().toLowerCase());
        }
    }

    @Test
    @DisplayName("case does not matter for the provider half")
    void providerCaseInsensitive() {
        assertThat(SocialRegistrationId.parse("acme-GOOGLE").orElseThrow().provider())
                .isEqualTo(SocialProviderType.GOOGLE);
    }

    @Test
    @DisplayName("anything malformed is empty, never an exception — these come off a URL")
    void malformedIsEmpty() {
        for (String bad : new String[]{
                null, "", "-", "google", "acme-", "-google", "acme-notaprovider", "acme-saml-okta"}) {
            assertThat(SocialRegistrationId.parse(bad))
                    .as("should not parse: %s", bad)
                    .isEmpty();
        }
    }
}
