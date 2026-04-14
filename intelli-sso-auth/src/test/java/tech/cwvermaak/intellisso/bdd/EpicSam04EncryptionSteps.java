package tech.cwvermaak.intellisso.bdd;

import io.cucumber.java.en.Given;
import io.cucumber.java.en.Then;
import io.cucumber.java.en.When;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import tech.cwvermaak.intellisso.service.pki.PemUtils;
import tech.cwvermaak.intellisso.service.saml.SamlAssertionEncrypter;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Base64;
import java.util.Date;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Exercises {@link SamlAssertionEncrypter} end-to-end: generate a
 * throwaway RSA keypair + self-signed cert, encrypt a known assertion
 * XML to it, then decrypt with the same private key and assert the
 * plaintext round-trips. The crypto path runs for real — no mocks.
 */
public class EpicSam04EncryptionSteps {

    private KeyPair keyPair;
    private String certPem;
    private String innerAssertionXml;
    private String encryptedXml;
    private String encryptedXml2;
    private String recovered;

    // ---- Given -----------------------------------------------------

    @Given("a fresh RSA test keypair with a self-signed certificate")
    public void freshKeypair() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(2048, new SecureRandom());
        keyPair = gen.generateKeyPair();

        X500Name subject = new X500Name("CN=SAM-04 Test SP");
        LocalDateTime now = LocalDateTime.now();
        Date from = Date.from(now.atZone(ZoneId.systemDefault()).toInstant());
        Date to = Date.from(now.plusYears(1).atZone(ZoneId.systemDefault()).toInstant());

        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                subject, new BigInteger(64, new SecureRandom()),
                from, to, subject, keyPair.getPublic());
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(keyPair.getPrivate());
        X509Certificate cert = new JcaX509CertificateConverter()
                .getCertificate(builder.build(signer));
        certPem = PemUtils.writeCertificate(cert);
    }

    @Given("an inner signed assertion XML {string}")
    public void innerAssertion(String xml) {
        // Cucumber's escaped-string parameter delivers the XML with
        // already-unescaped quotes, so no extra processing is needed.
        this.innerAssertionXml = xml;
    }

    // ---- When ------------------------------------------------------

    @When("the assertion is encrypted to the test certificate")
    public void encrypt() {
        encryptedXml = SamlAssertionEncrypter.encrypt(innerAssertionXml, certPem);
    }

    @When("the assertion is encrypted to the test certificate twice")
    public void encryptTwice() {
        encryptedXml = SamlAssertionEncrypter.encrypt(innerAssertionXml, certPem);
        encryptedXml2 = SamlAssertionEncrypter.encrypt(innerAssertionXml, certPem);
    }

    @When("the SP decrypts the EncryptedAssertion with its private key")
    public void decrypt() throws Exception {
        recovered = decryptXml(encryptedXml, (RSAPrivateKey) keyPair.getPrivate());
    }

    // ---- Then ------------------------------------------------------

    @Then("the output contains a {string} element")
    public void outputContainsElement(String localName) {
        assertThat(encryptedXml).contains("<" + localName);
    }

    @Then("the output references the {string} content algorithm")
    public void outputReferencesContentAlg(String fragment) {
        assertThat(encryptedXml).contains("http://www.w3.org/2001/04/xmlenc#" + fragment);
    }

    @Then("the output references the {string} key wrap algorithm")
    public void outputReferencesWrapAlg(String fragment) {
        assertThat(encryptedXml).contains("http://www.w3.org/2001/04/xmlenc#" + fragment);
    }

    @Then("the recovered assertion XML equals the original")
    public void recoveredEqualsOriginal() {
        assertThat(recovered).isEqualTo(innerAssertionXml);
    }

    @Then("the two ciphertexts are different")
    public void ciphertextsDiffer() {
        String ct1 = extractCipherValue(encryptedXml, 1);
        String ct2 = extractCipherValue(encryptedXml2, 1);
        assertThat(ct1).isNotEqualTo(ct2);
    }

    @Then("both decrypt back to the original")
    public void bothDecrypt() throws Exception {
        String a = decryptXml(encryptedXml, (RSAPrivateKey) keyPair.getPrivate());
        String b = decryptXml(encryptedXml2, (RSAPrivateKey) keyPair.getPrivate());
        assertThat(a).isEqualTo(innerAssertionXml);
        assertThat(b).isEqualTo(innerAssertionXml);
    }

    // ---- Decryption helpers ---------------------------------------

    /**
     * XML-Enc reference decryption path. Walks the EncryptedAssertion
     * DOM, pulls out the wrapped AES key + ciphertext, RSA-OAEP-unwraps
     * the AES key with the SP private key, then AES-256-CBC decrypts
     * the payload (IV is the first 16 bytes of the cipher value).
     */
    private static String decryptXml(String xml, RSAPrivateKey privateKey) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        var doc = dbf.newDocumentBuilder()
                .parse(new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8)));

        // The wrapped AES key is the first CipherValue under EncryptedKey.
        var keyNodes = doc.getElementsByTagNameNS(
                "http://www.w3.org/2001/04/xmlenc#", "EncryptedKey");
        String wrappedKeyB64 = firstCipherValue((org.w3c.dom.Element) keyNodes.item(0));
        // The encrypted payload is the *last* CipherValue in the document
        // — i.e. the one directly under EncryptedData, not the inner
        // CipherValue that belongs to EncryptedKey.
        var allCipherValues = doc.getElementsByTagNameNS(
                "http://www.w3.org/2001/04/xmlenc#", "CipherValue");
        String payloadB64 = allCipherValues.item(allCipherValues.getLength() - 1).getTextContent();

        byte[] wrappedKey = Base64.getDecoder().decode(wrappedKeyB64);
        byte[] payload = Base64.getDecoder().decode(payloadB64);

        Cipher rsa = Cipher.getInstance("RSA/ECB/OAEPWithSHA-1AndMGF1Padding");
        rsa.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] aesKeyBytes = rsa.doFinal(wrappedKey);

        byte[] iv = new byte[16];
        System.arraycopy(payload, 0, iv, 0, 16);
        byte[] ciphertext = new byte[payload.length - 16];
        System.arraycopy(payload, 16, ciphertext, 0, ciphertext.length);

        Cipher aes = Cipher.getInstance("AES/CBC/PKCS5Padding");
        aes.init(Cipher.DECRYPT_MODE, new SecretKeySpec(aesKeyBytes, "AES"), new IvParameterSpec(iv));
        byte[] plaintext = aes.doFinal(ciphertext);
        return new String(plaintext, StandardCharsets.UTF_8);
    }

    private static String firstCipherValue(org.w3c.dom.Element parent) {
        var list = parent.getElementsByTagNameNS(
                "http://www.w3.org/2001/04/xmlenc#", "CipherValue");
        return list.item(0).getTextContent();
    }

    /**
     * Returns the Nth CipherValue text (0-indexed) by doing a naive
     * parse — good enough for the "distinct ciphertexts" check.
     */
    private static String extractCipherValue(String xml, int index) {
        int from = 0;
        for (int i = 0; i <= index; i++) {
            int open = xml.indexOf("<xenc:CipherValue>", from);
            if (open < 0) return null;
            int start = open + "<xenc:CipherValue>".length();
            int end = xml.indexOf("</xenc:CipherValue>", start);
            if (i == index) return xml.substring(start, end);
            from = end;
        }
        return null;
    }
}
