package tech.cwvermaak.intellisso.model.dto;

import lombok.*;

/**
 * Admin-portal DTO for a tenant's Twilio configuration. The {@code authToken}
 * field is write-only: it accepts a new value on create/update but is never
 * returned in list/get responses. Leaving it null or empty on update means
 * "keep the existing value".
 */
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class TwilioProviderDto {

    private Long id;
    private Long tenantId;

    private String accountSid;

    /** Write-only. Never populated in GET responses. */
    private String authToken;

    private String fromPhone;
    private String messagingServiceSid;
    private Boolean enabled;

    /** Indicates whether an auth token has been set, without revealing it. */
    private Boolean authTokenSet;
}
