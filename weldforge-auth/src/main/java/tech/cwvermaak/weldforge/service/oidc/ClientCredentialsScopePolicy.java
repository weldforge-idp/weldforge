package tech.cwvermaak.weldforge.service.oidc;

import java.util.Arrays;
import java.util.List;

/**
 * The scopes a {@code client_credentials} token may carry (WF-7).
 *
 * <p>RFC 6749 §3.3 and §4.4.2: the authorization server may ignore the
 * requested scope in full or in part, but a token must never carry a scope the
 * client is not entitled to. The token endpoint had been echoing the requested
 * {@code scope} parameter verbatim into the access token, so a client
 * registered for {@code openid} alone could mint a token claiming
 * {@code admin:everything} merely by asking for it — the finding the
 * 2026-11-15 review raised and the local penetration test confirmed.
 *
 * <p>The client's registered scope list is the ceiling, exactly as it already
 * is for a refreshed token ({@code resolveRefreshScopes}). A requested scope
 * outside it is {@code invalid_scope} rather than silently dropped, so a
 * misconfigured caller is told its grant is wrong instead of quietly receiving
 * a token that does not say what it asked for. A client that needs a scope
 * registers it; nothing can be claimed that was not registered.
 */
public final class ClientCredentialsScopePolicy {

    private ClientCredentialsScopePolicy() {}

    /**
     * The scopes to put in the token.
     *
     * @param registered     the client's registered scope list — the ceiling;
     *                       null is treated as empty
     * @param requestedScope the raw space-delimited {@code scope} parameter, or
     *                       null when the client asked for none
     * @return the registered set when none is requested, otherwise the
     *         requested set once every entry has been checked against the ceiling
     * @throws OidcAuthorizationException {@code invalid_scope} when a requested
     *         scope is not registered for the client
     */
    public static List<String> resolve(List<String> registered, String requestedScope) {
        List<String> ceiling = registered == null ? List.of() : registered;
        if (requestedScope == null || requestedScope.isBlank()) {
            return ceiling;
        }
        List<String> requested = Arrays.stream(requestedScope.split("\\s+"))
                .filter(s -> !s.isBlank())
                .toList();
        for (String s : requested) {
            if (!ceiling.contains(s)) {
                throw new OidcAuthorizationException("invalid_scope",
                        "Scope '" + s + "' is not registered for this client");
            }
        }
        return requested;
    }
}
