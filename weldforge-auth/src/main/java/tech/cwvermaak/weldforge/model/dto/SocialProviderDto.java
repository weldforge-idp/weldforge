package tech.cwvermaak.weldforge.model.dto;

import lombok.*;
import tech.cwvermaak.weldforge.model.SocialProviderType;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class SocialProviderDto {
    private Long id;
    private Long tenantId;
    private SocialProviderType provider;
    private String displayName;
    private String clientId;
    /** Write-only: populated when creating/updating, never returned in GET responses. */
    private String clientSecret;
    private String scopes;
    private Boolean enabled;
    /**
     * Space-separated RFC 8176 methods asserted for sessions from this
     * provider. Admin-only: redacted on the public pre-login endpoint, because
     * a login page has no business knowing what the server will assert.
     */
    private String assertedAmr;
    /** Required Google {@code hd} values. Admin-only, redacted as above. */
    private String requiredHd;
    /** Convenience for the login page: the registrationId Spring will route by. */
    private String registrationId;
}
