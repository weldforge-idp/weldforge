package tech.cwvermaak.weldforge.service.oidc;

/**
 * Carries an OAuth2 / OIDC standard error code so the controller can
 * render the right response shape — query string redirect for
 * {@code /authorize} failures, JSON 400 for {@code /token} failures.
 */
public class OidcAuthorizationException extends RuntimeException {

    private final String errorCode;

    public OidcAuthorizationException(String errorCode, String message) {
        super(message);
        this.errorCode = errorCode;
    }

    public String getErrorCode() {
        return errorCode;
    }
}
