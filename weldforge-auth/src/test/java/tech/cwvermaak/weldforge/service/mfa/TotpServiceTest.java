package tech.cwvermaak.weldforge.service.mfa;

import dev.samstevens.totp.code.CodeGenerator;
import dev.samstevens.totp.code.DefaultCodeGenerator;
import dev.samstevens.totp.code.HashingAlgorithm;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Pure unit tests for {@link TotpService} — no Spring context, no DB.
 * Kept fast so they run on every CI build without slowing the feedback loop.
 */
class TotpServiceTest {

    private TotpService totp;

    @BeforeEach
    void setUp() {
        totp = new TotpService();
        ReflectionTestUtils.setField(totp, "issuer", "WeldForge");
    }

    @Test
    @DisplayName("generateSecret produces a non-empty base32 secret")
    void generateSecret_producesNonEmptyBase32() {
        String secret = totp.generateSecret();

        assertThat(secret).isNotNull().isNotBlank();
        // Base32 alphabet: A–Z + 2–7. Our default generator emits 32 chars.
        assertThat(secret).matches("[A-Z2-7]+");
        assertThat(secret.length()).isGreaterThanOrEqualTo(16);
    }

    @Test
    @DisplayName("verify accepts a freshly-generated code")
    void verify_acceptsValidCode() throws Exception {
        String secret = totp.generateSecret();
        // Compute the code the user's authenticator app would currently show.
        CodeGenerator codeGenerator = new DefaultCodeGenerator(HashingAlgorithm.SHA1, 6);
        long bucket = System.currentTimeMillis() / 1000 / 30;
        String code = codeGenerator.generate(secret, bucket);

        assertThat(totp.verify(secret, code)).isTrue();
    }

    @Test
    @DisplayName("verify rejects an obviously wrong code")
    void verify_rejectsWrongCode() {
        String secret = totp.generateSecret();
        assertThat(totp.verify(secret, "000000")).isFalse();
        assertThat(totp.verify(secret, "123456")).isFalse();
    }

    @Test
    @DisplayName("matchingStep returns the current time-step for a valid code (anti-replay support)")
    void matchingStep_returnsCurrentStep() throws Exception {
        String secret = totp.generateSecret();
        CodeGenerator codeGenerator = new DefaultCodeGenerator(HashingAlgorithm.SHA1, 6);
        long bucket = System.currentTimeMillis() / 1000 / 30;
        String code = codeGenerator.generate(secret, bucket);

        java.util.OptionalLong step = totp.matchingStep(secret, code);
        assertThat(step).isPresent();
        // Allow for a step rollover between code generation and verification.
        assertThat(step.getAsLong()).isBetween(bucket - 1, bucket + 1);
    }

    @Test
    @DisplayName("matchingStep is empty for a wrong code or null inputs")
    void matchingStep_emptyForInvalid() {
        String secret = totp.generateSecret();
        assertThat(totp.matchingStep(secret, "000000")).isEmpty();
        assertThat(totp.matchingStep(null, "000000")).isEmpty();
        assertThat(totp.matchingStep(secret, null)).isEmpty();
        assertThat(totp.matchingStep(secret, "  ")).isEmpty();
    }

    @Test
    @DisplayName("verify returns false on null inputs without throwing")
    void verify_handlesNullsSafely() {
        assertThat(totp.verify(null, "000000")).isFalse();
        assertThat(totp.verify("JBSWY3DPEHPK3PXP", null)).isFalse();
    }

    @Test
    @DisplayName("generateQrDataUri returns a base64 PNG data URI")
    void generateQrDataUri_returnsPngDataUri() throws Exception {
        String secret = totp.generateSecret();
        String uri = totp.generateQrDataUri(secret, "alice@example.com");

        assertThat(uri).startsWith("data:image/png;base64,");
        // Strip the prefix — the rest should decode as valid base64.
        String base64 = uri.substring("data:image/png;base64,".length());
        assertThat(base64).isNotBlank();
        assertThat(java.util.Base64.getDecoder().decode(base64)).isNotEmpty();
    }
}
