package tech.cwvermaak.weldforge.service.pki;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.util.io.pem.PemObject;

import java.io.StringReader;
import java.io.StringWriter;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

/**
 * Thin wrappers around Bouncy Castle's PEM reader/writer so the rest
 * of the PKI service stack can deal in {@link String} PEMs without
 * tripping over the IO-exception signatures on every line.
 */
public final class PemUtils {

    private PemUtils() {}

    public static String writeCertificate(X509Certificate cert) {
        return writePem("CERTIFICATE", encodeOrThrow(cert));
    }

    public static String writePrivateKey(PrivateKey key) {
        return writePem("PRIVATE KEY", key.getEncoded());
    }

    public static String writeCrl(byte[] crlEncoded) {
        return writePem("X509 CRL", crlEncoded);
    }

    public static X509Certificate readCertificate(String pem) {
        try (PEMParser parser = new PEMParser(new StringReader(pem))) {
            Object obj = parser.readObject();
            if (!(obj instanceof X509CertificateHolder holder)) {
                throw new IllegalArgumentException("PEM is not a certificate");
            }
            return new JcaX509CertificateConverter().getCertificate(holder);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to parse certificate PEM: " + e.getMessage(), e);
        }
    }

    public static PrivateKey readPrivateKey(String pem) {
        try (PEMParser parser = new PEMParser(new StringReader(pem))) {
            Object obj = parser.readObject();
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
            if (obj instanceof PEMKeyPair kp) {
                return converter.getKeyPair(kp).getPrivate();
            }
            if (obj instanceof PrivateKeyInfo pki) {
                return converter.getPrivateKey(pki);
            }
            throw new IllegalArgumentException("PEM is not a private key");
        } catch (Exception e) {
            throw new IllegalStateException("Failed to parse private key PEM: " + e.getMessage(), e);
        }
    }

    // ---- Internals -------------------------------------------------

    private static String writePem(String type, byte[] bytes) {
        try (StringWriter sw = new StringWriter();
             JcaPEMWriter writer = new JcaPEMWriter(sw)) {
            writer.writeObject(new PemObject(type, bytes));
            writer.flush();
            return sw.toString();
        } catch (Exception e) {
            throw new IllegalStateException("Failed to write " + type + " PEM: " + e.getMessage(), e);
        }
    }

    private static byte[] encodeOrThrow(X509Certificate cert) {
        try {
            return cert.getEncoded();
        } catch (Exception e) {
            throw new IllegalStateException("Failed to encode certificate: " + e.getMessage(), e);
        }
    }
}
