package tech.cwvermaak.weldforge.service.mfa;

import dev.samstevens.totp.code.*;
import dev.samstevens.totp.exceptions.QrGenerationException;
import dev.samstevens.totp.qr.QrData;
import dev.samstevens.totp.qr.QrGenerator;
import dev.samstevens.totp.qr.ZxingPngQrGenerator;
import dev.samstevens.totp.secret.DefaultSecretGenerator;
import dev.samstevens.totp.secret.SecretGenerator;
import dev.samstevens.totp.time.SystemTimeProvider;
import dev.samstevens.totp.time.TimeProvider;
import dev.samstevens.totp.util.Utils;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

/**
 * TOTP (RFC 6238) utilities: secret generation, QR enrollment URI, and code
 * verification with the standard ±1 step clock-drift window.
 */
@Service
@Slf4j
public class TotpService {

    /** Standard TOTP period and clock-drift tolerance (matches the enrollment QR). */
    private static final long PERIOD_SECONDS = 30L;
    private static final int WINDOW_STEPS = 1;

    private final SecretGenerator secretGenerator = new DefaultSecretGenerator();
    private final QrGenerator qrGenerator = new ZxingPngQrGenerator();
    private final TimeProvider timeProvider = new SystemTimeProvider();
    // DefaultCodeGenerator defaults to SHA1 / 6 digits — same params as the QR.
    private final CodeGenerator codeGenerator = new DefaultCodeGenerator();

    @Value("${app.mfa.totp.issuer:WeldForge}")
    private String issuer;

    /** @return a freshly generated Base32-encoded shared secret. */
    public String generateSecret() {
        return secretGenerator.generate();
    }

    /**
     * @return a {@code data:image/png;base64,...} URI the admin UI can embed
     * directly in an {@code <img>} tag for QR enrollment.
     */
    public String generateQrDataUri(String secret, String userIdentifier) throws QrGenerationException {
        QrData data = new QrData.Builder()
                .label(userIdentifier)
                .secret(secret)
                .issuer(issuer)
                .algorithm(HashingAlgorithm.SHA1)
                .digits(6)
                .period(30)
                .build();
        byte[] png = qrGenerator.generate(data);
        return Utils.getDataUriForImage(png, qrGenerator.getImageMimeType());
    }

    /** Standard 6-digit TOTP verification with ±1 step tolerance. */
    public boolean verify(String secret, String code) {
        return matchingStep(secret, code).isPresent();
    }

    /**
     * Verify a TOTP code and, if valid, return the time-step that matched.
     * Checks the ±1 step window (newest step first) and compares in constant
     * time. The returned step lets the caller enforce RFC 6238 anti-replay by
     * rejecting any step it has already accepted.
     *
     * @return the matched time-step (epoch-seconds / 30), or empty if invalid
     */
    public java.util.OptionalLong matchingStep(String secret, String code) {
        if (secret == null || code == null) return java.util.OptionalLong.empty();
        String c = code.trim();
        if (c.isEmpty()) return java.util.OptionalLong.empty();
        long bucket = Math.floorDiv(timeProvider.getTime(), PERIOD_SECONDS);
        for (long step = bucket + WINDOW_STEPS; step >= bucket - WINDOW_STEPS; step--) {
            try {
                String expected = codeGenerator.generate(secret, step);
                if (java.security.MessageDigest.isEqual(
                        expected.getBytes(java.nio.charset.StandardCharsets.UTF_8),
                        c.getBytes(java.nio.charset.StandardCharsets.UTF_8))) {
                    return java.util.OptionalLong.of(step);
                }
            } catch (dev.samstevens.totp.exceptions.CodeGenerationException ignored) {
                // Skip this step — a generation failure just means "no match here".
            }
        }
        return java.util.OptionalLong.empty();
    }
}
