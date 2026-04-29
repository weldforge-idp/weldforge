package tech.cwvermaak.intellisso.model.dto;

import lombok.*;
import tech.cwvermaak.intellisso.model.TenantSamlProvider;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class SamlProviderDto {
    private Long id;
    private Long tenantId;

    /** Short slug used in the registration id. Immutable after creation. */
    private String providerKey;
    private String displayName;

    private String idpEntityId;
    private String idpSsoUrl;
    private String idpSloUrl;
    private TenantSamlProvider.Binding ssoBinding;

    /** PEM-encoded X.509 cert. Write-only in non-admin responses. */
    private String idpSigningCertificate;

    private String nameIdFormat;
    private String emailAttribute;
    private String nameAttribute;

    private Boolean wantAssertionsSigned;
    private Boolean wantAuthnRequestSigned;

    private Boolean enabled;

    /** Convenience: the Spring registrationId Spring SAML routes under. */
    private String registrationId;

    /** Convenience: where the login page should post the SP-initiated auth request. */
    private String loginUrl;

    /** Convenience: where the tenant admin can download our SP metadata to hand to the IdP admin. */
    private String spMetadataUrl;
}
