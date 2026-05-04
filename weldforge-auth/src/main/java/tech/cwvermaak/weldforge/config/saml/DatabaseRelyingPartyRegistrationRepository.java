package tech.cwvermaak.weldforge.config.saml;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.saml2.core.Saml2X509Credential;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.Saml2MessageBinding;
import org.springframework.stereotype.Component;
import tech.cwvermaak.weldforge.model.TenantSamlProvider;
import tech.cwvermaak.weldforge.repository.TenantSamlProviderRepository;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Optional;

/**
 * Dynamic, per-tenant {@link RelyingPartyRegistrationRepository}. Mirrors the
 * dynamic OAuth2 {@code DatabaseClientRegistrationRepository} — each tenant's
 * SAML providers are stored as rows and looked up at request time.
 *
 * Registration id format:
 *
 *   {tenantSlug}-saml-{providerKey}
 *
 * e.g. {@code acme-saml-okta}. The {@code -saml-} infix keeps it distinct
 * from OAuth2 registration ids like {@code acme-google}.
 *
 * Spring's standard SAML filters work with zero additional wiring:
 *   - SP-initiated login:  /saml2/authenticate/acme-saml-okta
 *   - Assertion consumer:  /login/saml2/sso/acme-saml-okta
 *   - SP metadata:         /saml2/service-provider-metadata/acme-saml-okta
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class DatabaseRelyingPartyRegistrationRepository implements RelyingPartyRegistrationRepository {

    public static final String SAML_INFIX = "-saml-";

    private final TenantSamlProviderRepository samlRepository;

    @Override
    public RelyingPartyRegistration findByRegistrationId(String registrationId) {
        if (registrationId == null) return null;

        int idx = registrationId.indexOf(SAML_INFIX);
        if (idx <= 0 || idx + SAML_INFIX.length() >= registrationId.length()) return null;

        String tenantSlug  = registrationId.substring(0, idx);
        String providerKey = registrationId.substring(idx + SAML_INFIX.length());

        Optional<TenantSamlProvider> row = samlRepository
                .findByTenant_SlugAndProviderKeyAndEnabledTrue(tenantSlug, providerKey);
        if (row.isEmpty()) return null;

        try {
            return build(registrationId, row.get());
        } catch (Exception e) {
            log.error("Failed to build SAML relying-party registration for {}: {}",
                    registrationId, e.getMessage(), e);
            return null;
        }
    }

    private RelyingPartyRegistration build(String registrationId, TenantSamlProvider cfg) throws Exception {
        X509Certificate idpCert = parseCertificate(cfg.getIdpSigningCertificate());
        Saml2X509Credential verification = Saml2X509Credential.verification(idpCert);

        Saml2MessageBinding binding = switch (cfg.getSsoBinding()) {
            case REDIRECT -> Saml2MessageBinding.REDIRECT;
            case POST     -> Saml2MessageBinding.POST;
        };

        // {baseUrl} and {registrationId} are substituted by Spring at request
        // time so the same row works across dev/staging/prod without edits.
        RelyingPartyRegistration.Builder b = RelyingPartyRegistration.withRegistrationId(registrationId)
                .entityId("{baseUrl}/saml2/service-provider-metadata/{registrationId}")
                .assertionConsumerServiceLocation("{baseUrl}/login/saml2/sso/{registrationId}")
                .assertingPartyDetails(party -> party
                        .entityId(cfg.getIdpEntityId())
                        .singleSignOnServiceLocation(cfg.getIdpSsoUrl())
                        .singleSignOnServiceBinding(binding)
                        .wantAuthnRequestsSigned(Boolean.TRUE.equals(cfg.getWantAuthnRequestSigned()))
                        .verificationX509Credentials(creds -> creds.add(verification))
                );

        if (cfg.getIdpSloUrl() != null && !cfg.getIdpSloUrl().isBlank()) {
            b.singleLogoutServiceLocation("{baseUrl}/logout/saml2/slo")
             .assertingPartyDetails(party -> party
                     .singleLogoutServiceLocation(cfg.getIdpSloUrl())
                     .singleLogoutServiceBinding(binding));
        }

        if (cfg.getNameIdFormat() != null && !cfg.getNameIdFormat().isBlank()) {
            b.nameIdFormat(cfg.getNameIdFormat());
        }

        return b.build();
    }

    private static X509Certificate parseCertificate(String pem) throws Exception {
        if (pem == null || pem.isBlank()) {
            throw new IllegalArgumentException("IdP signing certificate is empty");
        }
        String normalised = pem.trim();
        if (!normalised.contains("BEGIN CERTIFICATE")) {
            // Allow raw base64 — wrap it for the CertificateFactory.
            normalised = "-----BEGIN CERTIFICATE-----\n"
                    + normalised.replaceAll("\\s+", "\n")
                    + "\n-----END CERTIFICATE-----";
        }
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        return (X509Certificate) cf.generateCertificate(
                new ByteArrayInputStream(normalised.getBytes(StandardCharsets.UTF_8)));
    }
}
