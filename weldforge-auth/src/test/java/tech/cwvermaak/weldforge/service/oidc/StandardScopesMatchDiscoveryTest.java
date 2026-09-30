package tech.cwvermaak.weldforge.service.oidc;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Field;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * {@code scopes_supported} must describe what the server actually accepts.
 *
 * <p>The discovery document advertised only {@code openid profile email}
 * while {@code OidcAuthorizationService} permitted the full standard set,
 * {@code offline_access} included. That is the direction of untruth that
 * breaks integrations quietly: a conformant client library validates the
 * scope it wants against the published list and declines to request one that
 * is absent, so the RP concludes the feature is unavailable and goes looking
 * for a server-side switch that does not exist. An adopter did exactly that.
 *
 * <p>These are two constants in two classes and nothing but this test stops
 * them drifting apart again.
 */
class StandardScopesMatchDiscoveryTest {

    @Test
    @DisplayName("the advertised scopes are exactly the ones the server enforces")
    @SuppressWarnings("unchecked")
    void advertised_equals_enforced() throws Exception {
        Field f = OidcAuthorizationService.class.getDeclaredField("STANDARD_OIDC_SCOPES");
        f.setAccessible(true);
        Set<String> enforced = (Set<String>) f.get(null);

        assertThat(OidcAuthorizationService.standardScopes())
                .containsExactlyInAnyOrderElementsOf(enforced);
    }

    @Test
    @DisplayName("offline_access is advertised — it is how an RP asks for a refresh token")
    void offline_access_is_advertised() {
        assertThat(OidcAuthorizationService.standardScopes()).contains("offline_access");
    }

    @Test
    @DisplayName("openid leads, because RFC 8414 readers scan for it first")
    void openid_is_first() {
        assertThat(OidcAuthorizationService.standardScopes()).first().isEqualTo("openid");
    }
}
