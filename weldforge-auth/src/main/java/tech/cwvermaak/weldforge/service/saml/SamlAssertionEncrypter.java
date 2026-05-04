package tech.cwvermaak.weldforge.service.saml;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;

/**
 * PRD SAM-04 — wraps a signed SAML {@code <Assertion>} in an
 * {@code <EncryptedAssertion>} using the W3C XML Encryption 1.0 shape.
 *
 * <p>Algorithm choices track the SAML profile baseline that every
 * mainstream SP supports:
 * <ul>
 *   <li>Content key: AES-256-CBC (PKCS#7 padding, random IV prepended to
 *       the ciphertext per XML-Enc §5.2).</li>
 *   <li>Key wrap: RSA-OAEP-MGF1-SHA1 using the SP's X.509 public key
 *       ({@code rsa-oaep-mgf1p} in XML-Enc terms).</li>
 * </ul>
 *
 * <p>The output XML is a string — {@link SamlIdpService} textually
 * substitutes the original assertion element for this block inside the
 * {@code <Response>}. Manual XML assembly is acceptable here because the
 * enclosing Response is already built the same way; we do not pull in
 * the DOM apparatus for one element.
 */
public final class SamlAssertionEncrypter {

    private static final SecureRandom RNG = new SecureRandom();

    private SamlAssertionEncrypter() {}

    /**
     * Encrypt {@code assertionXml} to {@code spCertPem} and return an
     * {@code <saml:EncryptedAssertion>...</saml:EncryptedAssertion>}
     * XML string. The {@code saml} namespace declaration is inlined so
     * the block can be dropped into any Response regardless of how the
     * enclosing document declared its prefixes.
     */
    public static String encrypt(String assertionXml, String spCertPem) {
        try {
            RSAPublicKey publicKey = loadPublicKey(spCertPem);

            // 1. Generate a random AES-256 key + IV and encrypt the assertion.
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(256, RNG);
            SecretKey aesKey = keyGen.generateKey();

            byte[] iv = new byte[16];
            RNG.nextBytes(iv);
            Cipher aes = Cipher.getInstance("AES/CBC/PKCS5Padding");
            aes.init(Cipher.ENCRYPT_MODE, aesKey, new IvParameterSpec(iv));
            byte[] ciphertext = aes.doFinal(assertionXml.getBytes(StandardCharsets.UTF_8));

            // Per XML-Enc §5.2, CipherValue = IV || ciphertext (both raw).
            byte[] ivPlusCt = new byte[iv.length + ciphertext.length];
            System.arraycopy(iv, 0, ivPlusCt, 0, iv.length);
            System.arraycopy(ciphertext, 0, ivPlusCt, iv.length, ciphertext.length);
            String encryptedDataB64 = Base64.getEncoder().encodeToString(ivPlusCt);

            // 2. Wrap the AES key with RSA-OAEP-MGF1-SHA1 under the SP's public key.
            Cipher rsa = Cipher.getInstance("RSA/ECB/OAEPWithSHA-1AndMGF1Padding");
            rsa.init(Cipher.ENCRYPT_MODE, publicKey);
            byte[] wrappedKey = rsa.doFinal(aesKey.getEncoded());
            String wrappedKeyB64 = Base64.getEncoder().encodeToString(wrappedKey);

            return "<saml:EncryptedAssertion xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\">"
                    + "<xenc:EncryptedData xmlns:xenc=\"http://www.w3.org/2001/04/xmlenc#\""
                    + " Type=\"http://www.w3.org/2001/04/xmlenc#Element\">"
                    + "<xenc:EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#aes256-cbc\"/>"
                    + "<ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">"
                    + "<xenc:EncryptedKey>"
                    + "<xenc:EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p\"/>"
                    + "<xenc:CipherData><xenc:CipherValue>" + wrappedKeyB64 + "</xenc:CipherValue></xenc:CipherData>"
                    + "</xenc:EncryptedKey>"
                    + "</ds:KeyInfo>"
                    + "<xenc:CipherData><xenc:CipherValue>" + encryptedDataB64 + "</xenc:CipherValue></xenc:CipherData>"
                    + "</xenc:EncryptedData>"
                    + "</saml:EncryptedAssertion>";
        } catch (Exception e) {
            throw new IllegalStateException("Failed to encrypt SAML assertion: " + e.getMessage(), e);
        }
    }

    private static RSAPublicKey loadPublicKey(String pem) throws Exception {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        byte[] der;
        String trimmed = pem == null ? "" : pem.trim();
        if (trimmed.startsWith("-----BEGIN")) {
            String b64 = trimmed
                    .replaceAll("-----BEGIN [^-]+-----", "")
                    .replaceAll("-----END [^-]+-----", "")
                    .replaceAll("\\s", "");
            der = Base64.getDecoder().decode(b64);
        } else {
            // Some SPs ship a raw base64 blob without the PEM framing.
            der = Base64.getDecoder().decode(trimmed.replaceAll("\\s", ""));
        }
        X509Certificate cert = (X509Certificate) cf.generateCertificate(
                new java.io.ByteArrayInputStream(der));
        return (RSAPublicKey) cert.getPublicKey();
    }
}
