package tech.cwvermaak.weldforge.service.oidc;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.List;
import java.util.Objects;

/**
 * Decides whether a requested {@code redirect_uri} matches one the client
 * registered.
 *
 * <p>The rule is exact string comparison, with one exception required by
 * RFC 8252 §7.3: for <em>loopback IP</em> redirect URIs the authorization
 * server "MUST allow any port to be specified at the time of the request".
 * A native app cannot reserve a port ahead of time — another process may
 * already hold it — so it asks the OS for an ephemeral one at login and only
 * then knows its own redirect URI. With exact matching such a client can
 * never authenticate: the port differs on every run.
 *
 * <p>Everything other than the port is still compared exactly, and the
 * exception is deliberately narrow:
 *
 * <ul>
 *   <li><b>IP literals only</b> — {@code 127.0.0.1} and {@code [::1]}, never
 *       {@code localhost}. RFC 8252 §8.3 warns that the hostname may resolve
 *       somewhere else entirely (a hosts-file entry, a DNS search domain, an
 *       attacker-controlled resolver), which would send the authorization
 *       code off-machine. The IP literal cannot be redirected that way.
 *       A client that registers {@code http://localhost:3000/cb} keeps
 *       working — it just gets exact matching, port included.</li>
 *   <li><b>Both sides must be loopback</b> — a registered loopback URI never
 *       relaxes matching for a non-loopback request, and vice versa.</li>
 *   <li><b>Scheme, host, path and query must be equal</b> — only the port is
 *       ignored. The path is compared raw, not normalised, so
 *       {@code /cb/../evil} does not match {@code /cb}.</li>
 *   <li><b>No userinfo, no fragment</b> — RFC 6749 §3.1.2 forbids a fragment
 *       on a redirect URI, and {@code http://evil@127.0.0.1/cb} is rejected
 *       rather than being treated as loopback.</li>
 * </ul>
 *
 * <p>Registering {@code http://127.0.0.1/callback} (no port) is the tidy way
 * to express "any ephemeral port on this path", but a registered URI that
 * does carry a port also matches any requested port — the port is simply not
 * part of the comparison once both sides are loopback.
 */
public final class RedirectUriMatcher {

    private RedirectUriMatcher() {
    }

    /**
     * @param registered the client's registered redirect URIs
     * @param requested  the {@code redirect_uri} from the request
     * @return true when {@code requested} matches one of {@code registered}
     */
    public static boolean matches(List<String> registered, String requested) {
        if (registered == null || registered.isEmpty() || requested == null || requested.isBlank()) {
            return false;
        }
        if (registered.contains(requested)) {
            return true;
        }
        Loopback wanted = Loopback.parse(requested);
        if (wanted == null) {
            return false;
        }
        for (String candidate : registered) {
            Loopback allowed = Loopback.parse(candidate);
            if (allowed != null && allowed.sameApartFromPort(wanted)) {
                return true;
            }
        }
        return false;
    }

    /**
     * A redirect URI that qualifies for port-agnostic comparison. Parsing
     * returns null for anything that does not — a non-loopback host, a
     * non-http scheme, a URI carrying userinfo or a fragment, or a string
     * that is not a valid URI at all — so the caller falls back to the exact
     * match it already performed.
     */
    private record Loopback(String scheme, String host, String path, String query) {

        static Loopback parse(String value) {
            URI uri;
            try {
                uri = new URI(value);
            } catch (URISyntaxException e) {
                return null;
            }
            if (!"http".equalsIgnoreCase(uri.getScheme())) {
                return null;
            }
            if (uri.getUserInfo() != null || uri.getFragment() != null) {
                return null;
            }
            String host = uri.getHost();
            if (!"127.0.0.1".equals(host) && !"[::1]".equals(host)) {
                return null;
            }
            return new Loopback("http", host,
                    uri.getRawPath() == null ? "" : uri.getRawPath(),
                    uri.getRawQuery());
        }

        boolean sameApartFromPort(Loopback other) {
            return scheme.equals(other.scheme)
                    && host.equals(other.host)
                    && path.equals(other.path)
                    && Objects.equals(query, other.query);
        }
    }
}
