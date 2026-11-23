package tech.cwvermaak.weldforge.service.oidc;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * WF-7 — a {@code client_credentials} token carries only scopes the client is
 * registered for. The endpoint used to echo the requested scope verbatim.
 */
class ClientCredentialsScopePolicyTest {

    private static final List<String> REGISTERED = List.of("api:read", "api:write");

    @Test
    @DisplayName("no requested scope yields the client's registered set")
    void defaultsToRegistered() {
        assertThat(ClientCredentialsScopePolicy.resolve(REGISTERED, null))
                .containsExactly("api:read", "api:write");
        assertThat(ClientCredentialsScopePolicy.resolve(REGISTERED, "   "))
                .containsExactly("api:read", "api:write");
    }

    @Test
    @DisplayName("a requested subset of the registered scopes is honoured")
    void narrowsToRequestedSubset() {
        assertThat(ClientCredentialsScopePolicy.resolve(REGISTERED, "api:read"))
                .containsExactly("api:read");
    }

    @Test
    @DisplayName("an unregistered scope is invalid_scope, not echoed into the token")
    void rejectsUnregisteredScope() {
        assertThatThrownBy(() -> ClientCredentialsScopePolicy.resolve(REGISTERED, "api:read admin:everything made:up"))
                .isInstanceOf(OidcAuthorizationException.class)
                .hasMessageContaining("admin:everything");
    }

    @Test
    @DisplayName("a client with no registered scopes can be granted none")
    void emptyCeilingRejectsAnyRequest() {
        assertThat(ClientCredentialsScopePolicy.resolve(List.of(), null)).isEmpty();
        assertThatThrownBy(() -> ClientCredentialsScopePolicy.resolve(List.of(), "anything"))
                .isInstanceOf(OidcAuthorizationException.class)
                .hasMessageContaining("anything");
    }

    @Test
    @DisplayName("a null registered list is treated as empty, never a wildcard")
    void nullRegisteredIsEmpty() {
        assertThat(ClientCredentialsScopePolicy.resolve(null, null)).isEmpty();
        assertThatThrownBy(() -> ClientCredentialsScopePolicy.resolve(null, "api:read"))
                .isInstanceOf(OidcAuthorizationException.class);
    }

    @Test
    @DisplayName("extra whitespace between requested scopes is ignored")
    void toleratesWhitespace() {
        assertThat(ClientCredentialsScopePolicy.resolve(REGISTERED, "  api:read   api:write "))
                .containsExactly("api:read", "api:write");
    }
}
