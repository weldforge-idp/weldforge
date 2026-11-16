package tech.cwvermaak.weldforge.service;

/**
 * A federated (social) sign-in the upstream provider accepted but this tenant
 * will not complete: the account is deactivated or locked, or the tenant
 * requires an MFA enrolment the browser flow cannot perform. Carries a short
 * code the callback hands to the login page, which explains it to the person.
 */
public class FederatedSignInRefusedException extends RuntimeException {

    public static final String ACCOUNT_UNAVAILABLE = "account_unavailable";
    public static final String MFA_ENROLLMENT_REQUIRED = "mfa_enrollment_required";

    private final String code;

    public FederatedSignInRefusedException(String code, String message) {
        super(message);
        this.code = code;
    }

    public String getCode() {
        return code;
    }
}
