package tech.cwvermaak.intellisso.model.dto;

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
}
