package tech.cwvermaak.weldforge.service.saml;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.PublicKey;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Spec for the XSW-resistant SAML signature validator (B-SAML-1 part a).
 * Real RSA signatures generated in-test via {@link SamlTestCrypto}, with
 * comprehensive positive and negative coverage.
 */
class SamlSignatureValidatorTest {

    private static KeyPair signer;
    private static KeyPair otherKey;

    @BeforeAll
    static void keys() throws Exception {
        signer = SamlTestCrypto.generateKeyPair();
        otherKey = SamlTestCrypto.generateKeyPair();
    }

    // ---- positive ----------------------------------------------------

    @Test
    @DisplayName("accepts a validly-signed AuthnRequest")
    void acceptsValidSignature() throws Exception {
        String signed = SamlTestCrypto.sign(
                SamlTestCrypto.authnRequest("https://sp.example.com", "_req1"), signer);

        assertThatCode(() -> SamlSignatureValidator.verify(signed, signer.getPublic()))
                .doesNotThrowAnyException();
    }

    @Test
    @DisplayName("publicKeyFromPem round-trips the signing key so an end-to-end PEM verify works")
    void pemRoundTripVerifies() throws Exception {
        String pem = SamlTestCrypto.selfSignedCertPem(signer);
        PublicKey fromPem = SamlSignatureValidator.publicKeyFromPem(pem);
        String signed = SamlTestCrypto.sign(
                SamlTestCrypto.authnRequest("https://sp.example.com", "_req2"), signer);

        assertThatCode(() -> SamlSignatureValidator.verify(signed, fromPem))
                .doesNotThrowAnyException();
    }

    // ---- negative ----------------------------------------------------

    @Test
    @DisplayName("rejects an unsigned AuthnRequest")
    void rejectsUnsigned() {
        String unsigned = SamlTestCrypto.authnRequest("https://sp.example.com", "_req3");

        assertThatThrownBy(() -> SamlSignatureValidator.verify(unsigned, signer.getPublic()))
                .isInstanceOf(SamlMessageException.class)
                .hasMessageContaining("not signed");
    }

    @Test
    @DisplayName("rejects a signature verified against the wrong key")
    void rejectsWrongKey() throws Exception {
        String signed = SamlTestCrypto.sign(
                SamlTestCrypto.authnRequest("https://sp.example.com", "_req4"), signer);

        assertThatThrownBy(() -> SamlSignatureValidator.verify(signed, otherKey.getPublic()))
                .isInstanceOf(SamlMessageException.class);
    }

    @Test
    @DisplayName("rejects a tampered message — the digest no longer matches")
    void rejectsTampered() throws Exception {
        String signed = SamlTestCrypto.sign(
                SamlTestCrypto.authnRequest("https://sp.example.com", "_req5"), signer);
        // Flip the issuer after signing — the reference digest must now fail.
        String tampered = signed.replace("https://sp.example.com", "https://evil.example.com");

        assertThatThrownBy(() -> SamlSignatureValidator.verify(tampered, signer.getPublic()))
                .isInstanceOf(SamlMessageException.class);
    }

    @Test
    @DisplayName("rejects a message with no ID to sign over")
    void rejectsNoId() throws Exception {
        // A signed doc whose root ID was stripped can't be bound to a reference.
        String signed = SamlTestCrypto.sign(
                SamlTestCrypto.authnRequest("https://sp.example.com", "_req6"), signer);
        String noId = signed.replaceFirst("ID=\"_req6\"", "");

        assertThatThrownBy(() -> SamlSignatureValidator.verify(noId, signer.getPublic()))
                .isInstanceOf(SamlMessageException.class);
    }
}
