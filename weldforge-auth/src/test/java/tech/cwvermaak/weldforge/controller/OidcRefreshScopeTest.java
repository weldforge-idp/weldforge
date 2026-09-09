package tech.cwvermaak.weldforge.controller;

import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;
import tech.cwvermaak.weldforge.model.OidcClient;
import tech.cwvermaak.weldforge.model.RefreshToken;
import tech.cwvermaak.weldforge.service.oidc.OidcAuthorizationException;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;

/**
 * CONF-1.1 — a refresh must not widen scope (RFC 6749 §6).
 *
 * <p>The refresh branch used to re-derive scope from {@code client.getScopeList()},
 * the client's whole registration. A user who consented to {@code openid email}
 * got everything the client was registered for back on the first refresh —
 * silently, permanently, and with no consent screen in between.
 *
 * <p>{@code resolveRefreshScopes} is the enforcement point. It is exercised
 * directly rather than through the token endpoint so the scope rules are pinned
 * independently of client authentication, rotation and token minting.
 */
class OidcRefreshScopeTest {

    private OidcAuthorizationController controller;
    private MeterRegistry meterRegistry;
    private OidcClient client;

    @BeforeEach
    void setUp() {
        meterRegistry = new SimpleMeterRegistry();
        controller = new OidcAuthorizationController(
                null, null, null, null, null, null, null, null, meterRegistry,
                mock(tech.cwvermaak.weldforge.repository.OidcConsentGrantRepository.class));

        client = new OidcClient();
        client.setClientId("portal");
        // Registration is deliberately WIDER than any grant below — that gap is
        // exactly what the old code leaked.
        client.setScopes("openid email profile admin:read admin:write");
    }

    @SuppressWarnings("unchecked")
    private List<String> resolve(String grantedScopes, String requestedScope) {
        RefreshToken row = RefreshToken.builder().grantedScopes(grantedScopes).build();
        return (List<String>) ReflectionTestUtils.invokeMethod(
                controller, "resolveRefreshScopes", row, client, requestedScope);
    }

    @Test
    @DisplayName("A refresh reissues what the user granted, not what the client registered")
    void reissues_the_granted_set() {
        assertThat(resolve("openid email", null))
                .as("the client is registered for admin:read/admin:write; the user granted neither")
                .containsExactly("openid", "email");
    }

    @Test
    @DisplayName("A client may narrow on refresh — RFC 6749 §6 permits it")
    void narrowing_is_allowed() {
        assertThat(resolve("openid email profile", "openid email"))
                .containsExactly("openid", "email");
    }

    @Test
    @DisplayName("A client may not widen past the grant, even to a registered scope")
    void widening_is_refused() {
        assertThatThrownBy(() -> resolve("openid email", "openid email admin:read"))
                .isInstanceOf(OidcAuthorizationException.class)
                .hasMessageContaining("admin:read")
                .satisfies(e -> assertThat(((OidcAuthorizationException) e).getErrorCode())
                        .isEqualTo("invalid_scope"));
    }

    @Test
    @DisplayName("A legacy family with no recorded grant falls back, and is metered")
    void legacy_family_falls_back_and_is_counted() {
        // Families minted before V48 have no granted_scopes. Breaking them at
        // deploy would log every live session out, so they fall back to the old
        // behaviour — but the fallback is counted so it can be retired on
        // evidence once the meter reads zero for longer than the refresh TTL.
        assertThat(resolve(null, null))
                .containsExactly("openid", "email", "profile", "admin:read", "admin:write");

        assertThat(meterRegistry.counter("sso.oidc.refresh.legacy_scope",
                "client_id", "portal").count()).isEqualTo(1.0);
    }

    @Test
    @DisplayName("A blank granted-scope string is treated as legacy, not as an empty grant")
    void blank_is_legacy_not_empty() {
        // An empty grant and an unknown grant are different things. Treating ""
        // as "granted nothing" would silently strip every scope from a family
        // whose column was written blank rather than null.
        assertThat(resolve("   ", null)).isNotEmpty();
        assertThat(meterRegistry.counter("sso.oidc.refresh.legacy_scope",
                "client_id", "portal").count()).isEqualTo(1.0);
    }

    @Test
    @DisplayName("A no-op refresh of a single-scope grant stays single-scope")
    void minimal_grant_is_preserved() {
        assertThat(resolve("openid", null)).containsExactly("openid");
    }
}
