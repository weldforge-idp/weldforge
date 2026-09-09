package tech.cwvermaak.weldforge.service.saml;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;
import tech.cwvermaak.weldforge.config.tenant.PublicHostProperties;
import tech.cwvermaak.weldforge.model.SamlServiceProvider;
import tech.cwvermaak.weldforge.model.Tenant;
import tech.cwvermaak.weldforge.model.TenantSigningKey;
import tech.cwvermaak.weldforge.repository.TenantSigningKeyRepository;
import tech.cwvermaak.weldforge.service.oidc.TenantSigningKeyService;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Sprint 5 — what the IdP asserts about itself and about the user should be
 * true.
 *
 * <p>Two of these failures were silent by construction. The authentication
 * context <em>under</em>-reported assurance, and nobody is alerted when
 * assurance is understated. The certificate mismatches each broke a different
 * SP implementation, so whichever one a tenant hit, the other two were somebody
 * else's problem.
 */
class SamlAssertionFidelityTest {

    private SamlIdpService idpService;
    private SamlSigningCertificateService certificateService;
    private Tenant leap;
    private TenantSigningKey key;
    private RSAPublicKey signingPublicKey;

    @BeforeEach
    void setUp() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair pair = generator.generateKeyPair();

        leap = Tenant.builder().id(1L).slug("leap").name("Leap").build();

        key = new TenantSigningKey();
        key.setId(100L);
        key.setKid("kid-1");
        key.setTenant(leap);

        TenantSigningKeyService signingKeyService = mock(TenantSigningKeyService.class);
        when(signingKeyService.getOrCreateActive(any())).thenReturn(key);
        signingPublicKey = (RSAPublicKey) pair.getPublic();
        when(signingKeyService.loadPublicKey(key)).thenReturn(signingPublicKey);
        when(signingKeyService.loadPrivateKey(key)).thenReturn((RSAPrivateKey) pair.getPrivate());

        TenantSigningKeyRepository keyRepository = mock(TenantSigningKeyRepository.class);
        when(keyRepository.findById(100L)).thenReturn(Optional.of(key));

        certificateService = new SamlSigningCertificateService(keyRepository, signingKeyService);

        PublicHostProperties publicHost = new PublicHostProperties();
        ReflectionTestUtils.setField(publicHost, "baseDomain", "sso.weldforge.org");
        ReflectionTestUtils.setField(publicHost, "scheme", "https");

        idpService = new SamlIdpService(
                null, null, signingKeyService, null, null, mock(
                        tech.cwvermaak.weldforge.service.audit.AuditService.class),
                certificateService, publicHost, null);
    }

    private SamlServiceProvider sp() {
        return SamlServiceProvider.builder()
                .id(10L).tenant(leap).entityId("https://rp.example.com/sp").build();
    }

    // ---- CONF-5.1 ----------------------------------------------------

    @Test
    @DisplayName("A password session is still described as password-protected")
    void password_session() {
        assertThat(idpService.resolveAuthnContext(sp(), List.of("pwd")))
                .isEqualTo(SamlIdpService.AUTHN_CTX_PASSWORD_PROTECTED);
    }

    @Test
    @DisplayName("A security key is not described as a password")
    void security_key_session() {
        // The defect this closes: a user who authenticated with a hardware key
        // was reported to the SP as having typed a password.
        assertThat(idpService.resolveAuthnContext(sp(), List.of("pwd", "hwk")))
                .isEqualTo(SamlIdpService.AUTHN_CTX_MOBILE_TWO_FACTOR);
    }

    @Test
    @DisplayName("A one-time code is described as a time-sync token")
    void otp_session() {
        assertThat(idpService.resolveAuthnContext(sp(), List.of("pwd", "otp")))
                .isEqualTo(SamlIdpService.AUTHN_CTX_TIME_SYNC_TOKEN);
    }

    @Test
    @DisplayName("The strongest factor wins when several were used")
    void strongest_factor_wins() {
        assertThat(idpService.resolveAuthnContext(sp(), List.of("pwd", "otp", "hwk")))
                .isEqualTo(SamlIdpService.AUTHN_CTX_MOBILE_TWO_FACTOR);
    }

    @Test
    @DisplayName("An unknown session falls back rather than guessing")
    void unknown_session_falls_back() {
        // Asserting something stronger than the evidence supports would be
        // worse than the understatement being fixed.
        assertThat(idpService.resolveAuthnContext(sp(), List.of()))
                .isEqualTo(SamlIdpService.AUTHN_CTX_PASSWORD_PROTECTED);
        assertThat(idpService.resolveAuthnContext(sp(), null))
                .isEqualTo(SamlIdpService.AUTHN_CTX_PASSWORD_PROTECTED);
    }

    @Test
    @DisplayName("An SP may pin a context and is never surprised")
    void sp_override_wins() {
        // The escape hatch for an SP that matches on a fixed value and would
        // otherwise break the day one of its users enables MFA.
        SamlServiceProvider pinned = sp();
        pinned.setAuthnContextOverride(SamlIdpService.AUTHN_CTX_PASSWORD_PROTECTED);

        assertThat(idpService.resolveAuthnContext(pinned, List.of("hwk")))
                .isEqualTo(SamlIdpService.AUTHN_CTX_PASSWORD_PROTECTED);
    }

    // ---- CONF-5.4 ----------------------------------------------------

    @Test
    @DisplayName("The published certificate really is an X.509 certificate")
    void certificate_parses_as_x509() throws Exception {
        // The metadata element has always been named <ds:X509Certificate> while
        // carrying a raw SubjectPublicKeyInfo, so an SP that parses it as the
        // name promises failed outright.
        String base64 = certificateService.base64Certificate(leap, key, "https://sso.weldforge.org/t/leap");

        byte[] der = java.util.Base64.getDecoder().decode(base64);
        X509Certificate parsed = (X509Certificate) java.security.cert.CertificateFactory
                .getInstance("X.509")
                .generateCertificate(new java.io.ByteArrayInputStream(der));

        assertThat(parsed).isNotNull();
        assertThat(parsed.getSubjectX500Principal().getName()).contains("sso.weldforge.org");
    }

    @Test
    @DisplayName("The certificate carries the signing key, not some other key")
    void certificate_wraps_the_signing_key() {
        X509Certificate certificate =
                certificateService.certificate(leap, key, "https://sso.weldforge.org/t/leap");

        // Compared against the ACTUAL signing key, not against the certificate's
        // own key -- the latter would be circular and pass for any certificate.
        // If these diverged, every signature would verify against a key the SP
        // could not obtain from metadata.
        assertThat(certificate.getPublicKey()).isEqualTo(signingPublicKey);
    }

    @Test
    @DisplayName("The certificate is minted once and then reused")
    void certificate_is_stable() {
        String first = certificateService.base64Certificate(leap, key, "https://sso.weldforge.org/t/leap");
        String second = certificateService.base64Certificate(leap, key, "https://sso.weldforge.org/t/leap");

        // A certificate that changed per call would rotate the metadata out
        // from under every SP that had pinned it.
        assertThat(first).isEqualTo(second);
    }

    @Test
    @DisplayName("The certificate is valid now and well beyond the key-rotation window")
    void certificate_validity() {
        X509Certificate certificate =
                certificateService.certificate(leap, key, "https://sso.weldforge.org/t/leap");

        assertThat(certificate.getNotBefore()).isBefore(new java.util.Date());
        assertThat(certificate.getNotAfter())
                .as("expiry in published metadata is an outage, not a control")
                .isAfter(java.util.Date.from(
                        java.time.Instant.now().plus(365, java.time.temporal.ChronoUnit.DAYS)));
    }

    @Test
    @DisplayName("The entityID used as Issuer matches the one metadata publishes")
    void entity_id_is_consistent() {
        // These must be byte-identical or an SP matching Issuer against
        // entityID rejects the assertion it was meant to accept.
        assertThat(idpService.metadataEntityId(leap))
                .isEqualTo("https://sso.weldforge.org/t/leap/saml2/idp/metadata");
    }
}
