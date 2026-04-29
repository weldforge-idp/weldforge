package tech.cwvermaak.intellisso.model.dto;

import lombok.*;

import java.util.Map;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class SamlServiceProviderDto {

    private Long id;
    private String entityId;
    private String name;
    private String acsUrl;
    private String sloUrl;
    private String spCertificate;
    private String nameIdFormat;
    private Map<String, Object> attributeMappings;
    private Boolean enabled;
    /** PRD SAM-04. When true and spCertificate is set, the IdP returns EncryptedAssertion. */
    private Boolean encryptAssertions;
}
