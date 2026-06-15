package tech.cwvermaak.weldforge.service.oidc;

/**
 * Carries an OAuth2 / OIDC standard error code so the controller can
 * render the right response shape — query string redirect for
 * {@code /authorize} failures, JSON 400 for {@code /token} failures.
 */
public class OidcAuthorizationException extends RuntimeException {

    private final String errorCode;
    /** When set, the {@code /authorize} handler redirects the error here (with state) instead of a JSON 400. */
    private final String redirectUri;
    private final String state;

    public OidcAuthorizationException(String errorCode, String message) {
        this(errorCode, message, null, null);
    }

    /**
     * Redirectable variant — use only after the {@code redirect_uri} has been
     * validated against the client's registered list (RFC 6749 §4.1.2.1).
     */
    public OidcAuthorizationException(String errorCode, String message, String redirectUri, String state) {
        super(message);
        this.errorCode = errorCode;
        this.redirectUri = redirectUri;
        this.state = state;
    }

    public String getErrorCode() {
        return errorCode;
    }

    public String getRedirectUri() {
        return redirectUri;
    }

    public String getState() {
        return state;
    }

    /** True when the error should be returned as a 302 to {@link #getRedirectUri()}. */
    public boolean isRedirectable() {
        return redirectUri != null && !redirectUri.isBlank();
    }
}
