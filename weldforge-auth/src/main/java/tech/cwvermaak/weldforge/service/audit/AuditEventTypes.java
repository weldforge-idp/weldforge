package tech.cwvermaak.weldforge.service.audit;

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
    public static final String MFA_CHALLENGE_BLOCKED  = "mfa.challenge.blocked";
    public static final String MFA_SELF_RESET         = "mfa.self_reset";
    public static final String MFA_ADMIN_RESET        = "mfa.admin_reset";
    public static final String MFA_BACKUP_CODES_REGENERATED = "mfa.backup_codes.regenerated";

    // Tenant management
    public static final String TENANT_CREATE          = "tenant.create";
    public static final String TENANT_UPDATE          = "tenant.update";
    public static final String TENANT_DELETE          = "tenant.delete";
    public static final String TENANT_PROVISIONED_VIA_BILLING = "tenant.provisioned_via_billing";

    /** Cross-tenant admin access via the X-WF-Tenant selector (cross-tenant-admin-spec.md). */
    public static final String ADMIN_CROSS_TENANT_ACCESS = "admin.cross_tenant.access";

    // V31: payment &amp; billing
    public static final String BILLING_ORDER_CREATED   = "billing.order.created";
    public static final String BILLING_ORDER_PAID      = "billing.order.paid";
    public static final String BILLING_ORDER_CANCELLED = "billing.order.cancelled";
    public static final String BILLING_ORDER_EXPIRED   = "billing.order.expired";
    public static final String BILLING_ORDER_REFUNDED  = "billing.order.refunded";
    public static final String BILLING_GATEWAY_CREATE  = "billing.gateway.create";
    public static final String BILLING_GATEWAY_UPDATE  = "billing.gateway.update";
    public static final String BILLING_GATEWAY_DELETE  = "billing.gateway.delete";
    public static final String BILLING_PROVISIONING_FAILED = "billing.provisioning.failed";

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

    // Federation rules (PRD FED-02 / FED-04)
    public static final String FEDERATION_RULES_UPDATE   = "federation.rules.update";

    // Service accounts (PRD TOK-03)
    public static final String SERVICE_ACCOUNT_CREATE = "service_account.create";
    public static final String SERVICE_ACCOUNT_ROTATE = "service_account.rotate";
    public static final String SERVICE_ACCOUNT_DELETE = "service_account.delete";

    // LDAP / AD upstream (PRD DIR-01 / DIR-02)
    public static final String LDAP_PROVIDER_UPSERT = "ldap_provider.upsert";
    public static final String LDAP_PROVIDER_DELETE = "ldap_provider.delete";

    // PKI (PRD §3.6 X50-01..X50-05)
    public static final String PKI_CA_CREATE         = "pki.ca.create";
    public static final String PKI_CERT_ISSUE        = "pki.cert.issue";
    public static final String PKI_CERT_REVOKE       = "pki.cert.revoke";
    public static final String PKI_CERT_EXPIRING     = "pki.cert.expiring";
    public static final String PKI_CLIENT_CERT_LOGIN = "pki.client_cert.login";

    // CRM provisioning (PRD §3.10 CRM-01..CRM-04)
    public static final String CRM_PROVIDER_UPSERT = "crm_provider.upsert";
    public static final String CRM_PROVIDER_DELETE = "crm_provider.delete";
    public static final String CRM_PROVISIONED    = "crm.provisioned";

    // Email verification
    public static final String AUTH_EMAIL_VERIFICATION_SENT = "auth.email.verification_sent";
    public static final String AUTH_EMAIL_VERIFIED          = "auth.email.verified";

    // Password reset
    public static final String AUTH_PASSWORD_RESET_REQUESTED = "auth.password_reset.requested";
    public static final String AUTH_PASSWORD_RESET_COMPLETED = "auth.password_reset.completed";
    public static final String AUTH_PASSWORD_CHANGED         = "auth.password.changed";
    public static final String AUTH_PASSWORD_CHANGE_FAILED   = "auth.password.change_failed";
    public static final String AUTH_PROFILE_UPDATED          = "auth.profile.updated";

    // User administration
    public static final String USER_DELETE            = "user.delete";
    public static final String USER_INVITED           = "user.invited";

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
    public static final String TARGET_SERVICE_ACCOUNT    = "service_account";
    public static final String TARGET_LDAP_PROVIDER      = "ldap_provider";
    public static final String TARGET_CERTIFICATE_AUTHORITY = "certificate_authority";
    public static final String TARGET_ISSUED_CERTIFICATE    = "issued_certificate";
    public static final String TARGET_CRM_PROVIDER          = "crm_provider";
}
