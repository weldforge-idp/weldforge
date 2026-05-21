package tech.cwvermaak.weldforge.model.dto;

import lombok.*;

import java.util.Map;

/**
 * Slim, unauthenticated DTO returned by {@code GET /api/auth/tenants/{slug}/branding}.
 * Carries everything the Angular login SPA needs to render a tenant-branded
 * login screen (logo + colours + copy) and to decide which optional links
 * to show ("Forgot your password?", "Create an account"). It deliberately
 * exposes no secrets — never add token TTLs, custom claims, etc. here.
 */
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class TenantBrandingDto {
    private String slug;
    private String displayName;
    private Boolean registrationEnabled;
    private Boolean passwordRecoveryEnabled;

    /**
     * Identity-proofing status — true when a platform super-admin has
     * marked the tenant as verified. The Angular auth-shell renders an
     * "Unverified tenant" warning badge when this is false, helping end
     * users spot a look-alike tenant on a wildcard-subdomain URL before
     * they type credentials. See {@code docs/auth-url-spec.md}
     * §"Tenant identity-proofing".
     */
    private Boolean verified;

    /** See {@code Tenant#branding} for the recognised keys. */
    private Map<String, Object> branding;
}
