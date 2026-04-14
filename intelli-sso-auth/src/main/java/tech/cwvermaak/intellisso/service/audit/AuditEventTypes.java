package tech.cwvermaak.intellisso.service.audit;

/**
 * Canonical list of audit event type strings. Kept as constants (not an enum)
 * so adding a new event does not require a schema change and the same column
 * can hold events added by future modules without coordination.
 */
public final class AuditEventTypes {

    private AuditEventTypes() {}

    // Authentication
    public static final String AUTH_LOGIN_SUCCESS       = "auth.login.success";
    public static final String AUTH_LOGIN_FAILED        = "auth.login.failed";
    public static final String AUTH_LOGIN_MFA_REQUIRED  = "auth.login.mfa_required";
    public static final String AUTH_REGISTER            = "auth.register";
    public static final String AUTH_LOGOUT_RP_INITIATED = "auth.logout.rp_initiated";

    // MFA
    public static final String MFA_FACTOR_ENROLL      = "mfa.factor.enroll";
    public static final String MFA_FACTOR_ACTIVATE    = "mfa.factor.activate";
    public static final String MFA_FACTOR_REMOVE      = "mfa.factor.remove";
    public static final String MFA_CHALLENGE_SUCCESS  = "mfa.challenge.success";
    public static final String MFA_CHALLENGE_FAILED   = "mfa.challenge.failed";
    public static final String MFA_SELF_RESET         = "mfa.self_reset";
    public static final String MFA_ADMIN_RESET        = "mfa.admin_reset";
    public static final String MFA_BACKUP_CODES_REGENERATED = "mfa.backup_codes.regenerated";

    // Tenant management
    public static final String TENANT_CREATE          = "tenant.create";
    public static final String TENANT_UPDATE          = "tenant.update";
    public static final String TENANT_DELETE          = "tenant.delete";

    // Provider config
    public static final String SOCIAL_PROVIDER_UPSERT = "social_provider.upsert";
    public static final String SOCIAL_PROVIDER_DELETE = "social_provider.delete";
    public static final String SAML_PROVIDER_UPSERT   = "saml_provider.upsert";
    public static final String SAML_PROVIDER_DELETE   = "saml_provider.delete";

    // Twilio per-tenant config
    public static final String TWILIO_PROVIDER_UPSERT = "twilio_provider.upsert";
    public static final String TWILIO_PROVIDER_DELETE = "twilio_provider.delete";

    // SMS MFA
    public static final String MFA_SMS_CODE_SENT     = "mfa.sms.code_sent";

    // MFA policy + step-up
    public static final String MFA_POLICY_UPSERT        = "mfa.policy.upsert";
    public static final String MFA_ENROLLMENT_REQUIRED  = "mfa.enrollment_required";
    public static final String MFA_STEPUP_REQUIRED      = "mfa.stepup_required";

    // SAML IdP
    public static final String SAML_IDP_ASSERTION_ISSUED = "saml_idp.assertion.issued";
    public static final String SAML_SP_CREATE            = "saml_idp.sp.create";
    public static final String SAML_SP_UPDATE            = "saml_idp.sp.update";
    public static final String SAML_SP_DELETE            = "saml_idp.sp.delete";

    // OIDC dynamic registration
    public static final String OIDC_CLIENT_DYNAMIC_REGISTER = "oidc.client.dynamic_register";

    // SAML SLO
    public static final String SAML_IDP_LOGOUT_INITIATED = "saml_idp.logout.initiated";

    // Group-Role binding
    public static final String GROUP_ROLE_MAPPING_CREATE = "group_role.mapping.create";
    public static final String GROUP_ROLE_MAPPING_DELETE = "group_role.mapping.delete";
    public static final String GROUP_ROLE_APPLY          = "group_role.apply";

    // Email verification
    public static final String AUTH_EMAIL_VERIFICATION_SENT = "auth.email.verification_sent";
    public static final String AUTH_EMAIL_VERIFIED          = "auth.email.verified";

    // Password reset
    public static final String AUTH_PASSWORD_RESET_REQUESTED = "auth.password_reset.requested";
    public static final String AUTH_PASSWORD_RESET_COMPLETED = "auth.password_reset.completed";

    // User administration
    public static final String USER_DELETE            = "user.delete";

    // Target types
    public static final String TARGET_USER               = "user";
    public static final String TARGET_TENANT             = "tenant";
    public static final String TARGET_MFA_FACTOR         = "mfa_factor";
    public static final String TARGET_SOCIAL_PROVIDER    = "social_provider";
    public static final String TARGET_SAML_PROVIDER      = "saml_provider";
    public static final String TARGET_SAML_SP            = "saml_service_provider";
    public static final String TARGET_GROUP_ROLE_MAPPING = "group_role_mapping";
    public static final String TARGET_OIDC_CLIENT        = "oidc_client";
    public static final String TARGET_TWILIO_PROVIDER    = "twilio_provider";
    public static final String TARGET_MFA_POLICY         = "mfa_policy";
}
