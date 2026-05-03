package tech.cwvermaak.weldforge.config.crypto;

import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Converter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * JPA attribute converter that transparently encrypts string columns
 * (currently used for per-tenant OAuth2 client secrets) with AES-GCM.
 *
 * The key is derived from {@code app.crypto.secret} via SHA-256. In
 * production this should come from a KMS / HSM — see PRD SEC-09.
 *
 * Ciphertext format (Base64-encoded):
 *   [12 bytes IV] || [ciphertext + 16-byte GCM tag]
 */
@Component
@Converter(autoApply = false)
public class EncryptedStringConverter implements AttributeConverter<String, String> {

    private static final String ALGO = "AES/GCM/NoPadding";
    private static final int IV_LENGTH_BYTES = 12;
    private static final int TAG_LENGTH_BITS = 128;

    // JPA instantiates converters without Spring injection in some paths, so
    // we hold the key statically once Spring has primed it.
    private static volatile SecretKey KEY;
    private static final SecureRandom RNG = new SecureRandom();

    @Value("${app.crypto.secret:}")
    private String configuredSecret;

    @jakarta.annotation.PostConstruct
    void init() {
        if (configuredSecret == null || configuredSecret.isBlank()) {
            throw new IllegalStateException(
                "app.crypto.secret must be set — required for at-rest encryption of tenant client secrets");
        }
        try {
            MessageDigest sha = MessageDigest.getInstance("SHA-256");
            KEY = new SecretKeySpec(sha.digest(configuredSecret.getBytes()), "AES");
        } catch (Exception e) {
            throw new IllegalStateException("Failed to initialise encryption key", e);
        }
    }

    @Override
    public String convertToDatabaseColumn(String plaintext) {
        if (plaintext == null) return null;
        SecretKey key = requireKey();
        try {
            byte[] iv = new byte[IV_LENGTH_BYTES];
            RNG.nextBytes(iv);
            Cipher cipher = Cipher.getInstance(ALGO);
            cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(TAG_LENGTH_BITS, iv));
            byte[] cipherText = cipher.doFinal(plaintext.getBytes());
            ByteBuffer buf = ByteBuffer.allocate(iv.length + cipherText.length);
            buf.put(iv).put(cipherText);
            return Base64.getEncoder().encodeToString(buf.array());
        } catch (Exception e) {
            throw new IllegalStateException("Failed to encrypt value", e);
        }
    }

    @Override
    public String convertToEntityAttribute(String ciphertext) {
        if (ciphertext == null) return null;
        SecretKey key = requireKey();
        try {
            byte[] raw = Base64.getDecoder().decode(ciphertext);
            if (raw.length < IV_LENGTH_BYTES + 16) {
                throw new IllegalStateException("Stored ciphertext is too short");
            }
            byte[] iv = new byte[IV_LENGTH_BYTES];
            System.arraycopy(raw, 0, iv, 0, IV_LENGTH_BYTES);
            byte[] ct = new byte[raw.length - IV_LENGTH_BYTES];
            System.arraycopy(raw, IV_LENGTH_BYTES, ct, 0, ct.length);
            Cipher cipher = Cipher.getInstance(ALGO);
            cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(TAG_LENGTH_BITS, iv));
            return new String(cipher.doFinal(ct));
        } catch (Exception e) {
            throw new IllegalStateException("Failed to decrypt value", e);
        }
    }

    private SecretKey requireKey() {
        SecretKey k = KEY;
        if (k == null) {
            throw new IllegalStateException(
                "EncryptedStringConverter used before Spring initialisation primed the key");
        }
        return k;
    }
}
