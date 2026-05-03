package tech.cwvermaak.weldforge.service.payment.gateway;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.Map;
import java.util.Objects;

/**
 * Decoded gateway credentials, parsed from the JSON blob stored in
 * {@code payment_gateways.credentials_encrypted} after JPA transparently
 * decrypts the column via {@code EncryptedStringConverter}.
 *
 * <p>Never log, serialise, or persist the returned map. It is owned
 * by the calling thread for the duration of one gateway operation.
 *
 * <p>Stripe example shape:
 * <pre>{
 *   "secret_key":     "sk_live_...",
 *   "publishable_key":"pk_live_...",
 *   "webhook_secret": "whsec_..."
 * }</pre>
 */
public record GatewayCredentials(Map<String, String> values) {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final TypeReference<Map<String, String>> TR = new TypeReference<>() {};

    public GatewayCredentials {
        Objects.requireNonNull(values);
    }

    public String require(String key) {
        String v = values.get(key);
        if (v == null || v.isBlank()) {
            throw new IllegalStateException("Missing credential: " + key);
        }
        return v;
    }

    public String get(String key) {
        return values.get(key);
    }

    /** Parse the JSON string stored (and auto-decrypted by JPA) into this wrapper. */
    public static GatewayCredentials decode(String jsonPlaintext) {
        try {
            return new GatewayCredentials(MAPPER.readValue(jsonPlaintext, TR));
        } catch (Exception e) {
            throw new IllegalStateException("Failed to parse gateway credentials JSON", e);
        }
    }

    /** Encode a plaintext map ready for {@code PaymentGateway.credentialsEncrypted}. */
    public static String encode(Map<String, String> values) {
        try {
            return MAPPER.writeValueAsString(values);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to encode gateway credentials JSON", e);
        }
    }
}
