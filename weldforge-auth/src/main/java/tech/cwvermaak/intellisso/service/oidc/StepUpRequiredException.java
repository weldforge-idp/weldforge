package tech.cwvermaak.intellisso.service.oidc;

/**
 * Thrown during an OIDC /authorize flow when the target client requires
 * MFA step-up — either because {@code require_mfa} is set, or because
 * {@code max_authentication_age_s} has elapsed since the user's last
 * verified factor use.
 *
 * The controller catches this and redirects to the MFA challenge flow
 * instead of issuing an authorization code.
 *
 * PRD: MFA-04, SSO-05.
 */
public class StepUpRequiredException extends OidcAuthorizationException {

    private final String clientId;

    public StepUpRequiredException(String clientId, String message) {
        super("mfa_required", message);
        this.clientId = clientId;
    }

    public String getClientId() {
        return clientId;
    }
}
