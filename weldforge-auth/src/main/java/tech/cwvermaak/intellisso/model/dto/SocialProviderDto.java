package tech.cwvermaak.intellisso.model.dto;

import lombok.*;
import tech.cwvermaak.intellisso.model.SocialProviderType;

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
    /** Convenience for the login page: the registrationId Spring will route by. */
    private String registrationId;
}
