package tech.cwvermaak.weldforge.model.dto;

import lombok.*;

import java.util.Map;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class TenantDto {
    private Long id;
    private String slug;
    private String name;
    private String displayName;
    private Boolean enabled;

    /** PRD SSO-03: access token TTL (ms). Null = application default. */
    private Long accessTtlMs;

    /** PRD SSO-03: refresh token TTL (ms). Null = application default. */
    private Long refreshTtlMs;

    /** PRD OA2-07: custom claims injected into every access + ID token. */
    private Map<String, Object> customClaims;

    /** Self-service registration on the login page. */
    private Boolean registrationEnabled;

    /** "Forgot your password?" link on the login page. */
    private Boolean passwordRecoveryEnabled;

    /** Require email verification before a self-registered user can sign in. */
    private Boolean emailVerificationRequired;

    /** Return the user to the calling app/login flow after a password reset. */
    private Boolean returnToCallerEnabled;

    /** Custom-login branding (logoUrl, primaryColor, tagline, …). */
    private Map<String, Object> branding;
}
