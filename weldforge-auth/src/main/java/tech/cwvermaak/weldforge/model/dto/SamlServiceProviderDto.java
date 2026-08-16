package tech.cwvermaak.weldforge.model.dto;

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
    /**
     * B-SAML-1(a). When true (and spCertificate is set), the IdP verifies the
     * XML signature on this SP's inbound AuthnRequest / LogoutRequest messages
     * and rejects unsigned or invalid ones.
     */
    private Boolean wantAuthnRequestSigned;
}
