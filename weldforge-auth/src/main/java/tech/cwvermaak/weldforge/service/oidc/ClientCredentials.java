package tech.cwvermaak.weldforge.service.oidc;

import jakarta.servlet.http.HttpServletRequest;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * Client credentials presented at the token, introspection or revocation
 * endpoint, resolved from either supported authentication method (CONF-4.1).
 *
 * <h3>Why this exists</h3>
 * RFC 6749 §2.3.1 says an authorization server <b>MUST</b> support HTTP Basic
 * and <em>may</em> also accept credentials in the request body. WeldForge
 * accepted only the body, so a client library configured the conformant way —
 * which for most libraries is the default — could not authenticate at all. The
 * discovery document was honest about it, but dynamic registration then handed
 * new clients {@code client_secret_basic} as their method, which the server
 * could not parse. Three components disagreed about the same contract.
 *
 * <h3>The rules</h3>
 * <ul>
 *   <li><b>Basic wins when present.</b> §2.3.1 calls it the preferred method.</li>
 *   <li><b>Never both.</b> A client <b>MUST NOT</b> use more than one method in
 *       a single request. Silently preferring one would let a caller smuggle a
 *       second identity past whichever layer looked at the other, so a request
 *       carrying both is rejected outright rather than resolved.</li>
 *   <li><b>Malformed Basic is a refusal, not a fallthrough.</b> A header that is
 *       present but undecodable means the caller intended to authenticate and
 *       got it wrong; treating that as "no header" and falling back to form
 *       parameters would turn a client bug into a confusing 401 somewhere else.</li>
 * </ul>
 *
 * <p>Per §2.3.1 the userid and password in a Basic header are
 * {@code application/x-www-form-urlencoded}-encoded before base64. Most clients
 * send credentials with no reserved characters and so never exercise this, which
 * is exactly why it is easy to get wrong and worth doing here rather than at
 * three call sites.
 */
public record ClientCredentials(String clientId, String clientSecret) {

    private static final String BASIC_PREFIX = "Basic ";

    /**
     * Resolve the credentials for this request.
     *
     * @param formClientId     the {@code client_id} form parameter, or null
     * @param formClientSecret the {@code client_secret} form parameter, or null
     * @return the resolved credentials; {@code clientSecret} may be null for a
     *         public client, which authenticates by {@code client_id} alone
     * @throws OidcAuthorizationException {@code invalid_client} when both
     *         methods are used at once, or when a Basic header is malformed
     */
    public static ClientCredentials resolve(HttpServletRequest request,
                                            String formClientId,
                                            String formClientSecret) {
        String header = request == null ? null : request.getHeader("Authorization");
        boolean hasBasic = header != null && header.startsWith(BASIC_PREFIX);

        if (!hasBasic) {
            return new ClientCredentials(formClientId, formClientSecret);
        }

        // §2.3.1: "The client MUST NOT use more than one authentication method
        // in each request." A secret in the body alongside a Basic header is
        // that case. A bare client_id is not -- clients routinely echo it for
        // logging, and rejecting those would break working integrations for no
        // security gain, since the Basic header is what actually authenticates.
        if (formClientSecret != null && !formClientSecret.isBlank()) {
            throw new OidcAuthorizationException("invalid_client",
                    "Use either HTTP Basic or client_secret_post, not both");
        }

        String decoded;
        try {
            decoded = new String(Base64.getDecoder().decode(header.substring(BASIC_PREFIX.length()).trim()),
                    StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            throw new OidcAuthorizationException("invalid_client",
                    "Malformed HTTP Basic credentials");
        }

        int separator = decoded.indexOf(':');
        if (separator < 0) {
            throw new OidcAuthorizationException("invalid_client",
                    "Malformed HTTP Basic credentials");
        }

        // A secret may legitimately contain a colon; the userid may not, so the
        // FIRST colon is the separator and everything after it is the secret.
        String id = urlDecode(decoded.substring(0, separator));
        String secret = urlDecode(decoded.substring(separator + 1));

        if (id.isBlank()) {
            throw new OidcAuthorizationException("invalid_client",
                    "Malformed HTTP Basic credentials");
        }

        // A client_id in the body must agree with the authenticated one, or the
        // request is asking two different questions at once.
        if (formClientId != null && !formClientId.isBlank() && !formClientId.equals(id)) {
            throw new OidcAuthorizationException("invalid_client",
                    "client_id does not match the authenticated client");
        }

        return new ClientCredentials(id, secret.isEmpty() ? null : secret);
    }

    /**
     * Reverse the {@code application/x-www-form-urlencoded} encoding §2.3.1
     * requires on each half of a Basic credential.
     *
     * <p>Decoding is best-effort: a client that did not encode its credentials
     * still authenticates as long as the raw value round-trips, which is the
     * common case. A value that is not valid percent-encoding is passed through
     * unchanged rather than rejected — the comparison against the stored secret
     * is what decides, and failing here would refuse a client whose secret
     * merely contains a stray {@code %}.
     */
    private static String urlDecode(String value) {
        try {
            return java.net.URLDecoder.decode(value, StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            return value;
        }
    }
}
