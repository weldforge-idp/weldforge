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
    /**
     * CONF-5.1. When set, every assertion to this SP carries this
     * {@code AuthnContextClassRef} verbatim instead of one derived from the
     * session. On update, null leaves it unchanged and an empty string clears
     * it -- which is how an SP pinned by V56 moves to the truthful value.
     */
    private String authnContextOverride;
    /**
     * CONF-5.4. When true, messages to this SP carry the metadata entityID as
     * {@code Issuer} instead of the legacy {@code {slug}-idp}. Reconfigure the
     * SP to expect the entityID first, then turn this on.
     */
    private Boolean useEntityIdAsIssuer;
}
