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

    private final SecretGenerator secretGenerator = new DefaultSecretGenerator();
    private final QrGenerator qrGenerator = new ZxingPngQrGenerator();
    private final TimeProvider timeProvider = new SystemTimeProvider();
    private final CodeVerifier codeVerifier =
            new DefaultCodeVerifier(new DefaultCodeGenerator(), timeProvider);

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
        if (secret == null || code == null) return false;
        return codeVerifier.isValidCode(secret, code.trim());
    }
}
