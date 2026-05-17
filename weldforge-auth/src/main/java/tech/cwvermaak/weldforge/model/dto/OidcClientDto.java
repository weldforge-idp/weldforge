package tech.cwvermaak.weldforge.model.dto;

import lombok.*;

import java.util.List;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class OidcClientDto {
    private Long id;
    private Long tenantId;
    private String clientId;
    /** Returned only on create / rotate so the caller can copy it once. */
    private String clientSecret;
    private String name;
    private List<String> redirectUris;
    private List<String> scopes;
    private List<String> grantTypes;
    private Boolean requirePkce;

    /** PRD MFA-04: force a verified MFA factor for every authorize. */
    private Boolean requireMfa;

    /**
     * PRD SSO-05: maximum age (seconds) of the user's last verified factor
     * use before step-up is required. 0 = use tenant default.
     */
    private Integer maxAuthenticationAgeSeconds;

    /** Browser origins allowed to call the tenant OIDC endpoints cross-origin. */
    private List<String> webOrigins;

    /** OIDC RP-Initiated Logout post_logout_redirect_uri allow-list. */
    private List<String> postLogoutRedirectUris;

    /**
     * Public client (PKCE-only, no client secret). May be set directly or
     * inferred from {@code tokenEndpointAuthMethod == "none"} on create.
     */
    private Boolean publicClient;

    /** RFC 8414 token_endpoint_auth_method: {@code client_secret_post} or {@code none}. */
    private String tokenEndpointAuthMethod;
}
