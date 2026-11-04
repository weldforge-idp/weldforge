package tech.cwvermaak.weldforge.config.security;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Boot-time secret hygiene, with the key ring (B-JWT-2 / CONF-7.4) included.
 *
 * <p>The reason the retired keys are checked at all: a verification key is as
 * powerful as a signing key for the purpose that matters — anyone holding one
 * can mint a token this server accepts. So a weak entry in
 * {@code app.jwt.previous-secrets} is a forgery oracle, not untidiness, and it
 * must fail the boot rather than warn.
 */
@DisplayName("Secret hygiene")
class SecretHygieneValidatorTest {

    private static final String GOOD =
            "a-perfectly-adequate-sixty-four-byte-secret-0123456789012345678901";
    private static final String ALSO_GOOD =
            "another-perfectly-adequate-sixty-four-byte-secret-98765432109876543";
    private static final String DEV_DEFAULT =
            "dev-only-insecure-jwt-secret-do-not-use-in-production-change-me-now-0123456789";

    private static SecretHygieneValidator validator(String jwt, String previous, boolean requireSecure) {
        SecretHygieneValidator v = new SecretHygieneValidator();
        ReflectionTestUtils.setField(v, "jwtSecret", jwt);
        ReflectionTestUtils.setField(v, "jwtPreviousSecrets", previous);
        ReflectionTestUtils.setField(v, "cryptoSecret", "a-fine-crypto-secret-value");
        ReflectionTestUtils.setField(v, "requireSecureSecrets", requireSecure);
        return v;
    }

    private static void validate(SecretHygieneValidator v) {
        ReflectionTestUtils.invokeMethod(v, "validate");
    }

    @Test
    @DisplayName("no rotation in progress is fine — the normal state")
    void noPreviousSecrets() {
        assertThatCode(() -> validate(validator(GOOD, "", true))).doesNotThrowAnyException();
        assertThatCode(() -> validate(validator(GOOD, null, true))).doesNotThrowAnyException();
    }

    @Test
    @DisplayName("a strong retired key during an overlap is fine")
    void strongPreviousSecret() {
        assertThatCode(() -> validate(validator(GOOD, ALSO_GOOD, true))).doesNotThrowAnyException();
    }

    @Test
    @DisplayName("a short retired key refuses to boot — it would accept forged tokens")
    void shortPreviousSecretRefusesBoot() {
        assertThatThrownBy(() -> validate(validator(GOOD, "too-short", true)))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("app.jwt.previous-secrets[0]")
                .hasMessageContaining("same standard as the signing key");
    }

    @Test
    @DisplayName("the floor applies in dev too, not only when secure-secrets is enforced")
    void shortPreviousSecretRefusesBootInDevAlso() {
        // Layer 1 is unconditional. A 64-byte floor is a genuine
        // misconfiguration anywhere, and a dev box that accepts a weak
        // verification key teaches the wrong habit.
        assertThatThrownBy(() -> validate(validator(GOOD, "too-short", false)))
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    @DisplayName("a comma inside one secret is caught as a mis-split, with the cause named")
    void commaInsideASecretIsCaughtAsMisSplit() {
        // The one mistake the comma-separated format invites. Both halves fall
        // under the floor, so the boot fails loudly instead of the server
        // quietly trusting two fragments as keys.
        String withComma = GOOD.substring(0, 30) + "," + GOOD.substring(30);

        assertThatThrownBy(() -> validate(validator(GOOD, withComma, true)))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("contains a comma");
    }

    @Test
    @DisplayName("a dev default among the retired keys refuses to boot when enforcement is on")
    void devDefaultAsPreviousSecretRefusesBoot() {
        assertThatThrownBy(() -> validate(validator(GOOD, DEV_DEFAULT, true)))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("previous-secrets");
    }

    @Test
    @DisplayName("several strong retired keys are allowed")
    void severalStrongPreviousSecrets() {
        assertThatCode(() -> validate(validator(GOOD, ALSO_GOOD + "," + DEV_DEFAULT, false)))
                .doesNotThrowAnyException();
    }

    @Test
    @DisplayName("the signing key's own floor is unchanged")
    void signingKeyFloorUnchanged() {
        assertThatThrownBy(() -> validate(validator("short", "", false)))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("app.jwt.secret must be at least");
    }
}
