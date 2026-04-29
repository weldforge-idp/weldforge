package tech.cwvermaak.intellisso.service.webhook;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

/**
 * HMAC-SHA256 signing for outbound webhook bodies (PRD API-06). The
 * receiver recomputes the signature over the raw request body using the
 * shared subscription secret and compares with the
 * {@code X-WeldForge-Signature} header.
 *
 * <p>The header carries both a timestamp and the signature to mitigate
 * replay attacks:
 * <pre>
 * X-WeldForge-Signature: t=1712999999,v1=abc123...
 * </pre>
 * where {@code v1} is lowercased hex HMAC-SHA256 over {@code t . "." . body}.
 */
public final class WebhookSigner {

    public static final String HEADER = "X-WeldForge-Signature";
    public static final String ALGORITHM = "HmacSHA256";

    private WebhookSigner() {}

    public static String sign(String secret, long timestamp, String body) {
        try {
            Mac mac = Mac.getInstance(ALGORITHM);
            mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), ALGORITHM));
            String signed = timestamp + "." + body;
            return HexFormat.of().formatHex(mac.doFinal(signed.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new IllegalStateException("HMAC-SHA256 unavailable", e);
        }
    }

    public static String header(long timestamp, String signatureHex) {
        return "t=" + timestamp + ",v1=" + signatureHex;
    }
}
