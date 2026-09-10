package tech.cwvermaak.weldforge.service.security;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class PasswordPolicyServiceTest {

    private PasswordPolicyProperties props;
    private PasswordPolicyService service;
    /** Passwords handed to the breach screen, in order. */
    private final List<String> screened = new ArrayList<>();
    private BreachedPasswordScreen.Result screenAnswer = BreachedPasswordScreen.Result.CLEAN;

    @BeforeEach
    void setUp() {
        props = new PasswordPolicyProperties();
        service = new PasswordPolicyService(props, password -> {
            screened.add(password);
            return screenAnswer;
        });
    }

    // ---- NIST SP 800-63B defaults (CONF-7.1) --------------------------

    @Test
    @DisplayName("defaults follow 800-63B: 12-character floor, no composition rules")
    void defaults_followNist() {
        assertThat(props.getMinLength()).isEqualTo(12);
        assertThat(props.isRequireUppercase()).isFalse();
        assertThat(props.isRequireLowercase()).isFalse();
        assertThat(props.isRequireDigit()).isFalse();
        assertThat(props.isRequireSymbol()).isFalse();
        assertThat(props.getBreachCheck().isEnabled()).isTrue();
    }

    @Test
    @DisplayName("accepts a long passphrase with no digits, symbols or capitals")
    void accepts_passphrase() {
        assertThatCode(() -> service.validate("correct horse battery staple"))
                .doesNotThrowAnyException();
    }

    @Test
    @DisplayName("rejects too-short passwords with a clear reason")
    void rejects_tooShort() {
        assertThatThrownBy(() -> service.validate("Ab1!"))
                .isInstanceOf(PasswordPolicyViolation.class)
                .satisfies(e -> {
                    PasswordPolicyViolation v = (PasswordPolicyViolation) e;
                    assertThat(v.getReasons())
                            .anyMatch(r -> r.contains("at least " + props.getMinLength()));
                });
    }

    @Test
    @DisplayName("rejects a breached password and says so")
    void rejects_breached() {
        screenAnswer = BreachedPasswordScreen.Result.BREACHED;

        assertThatThrownBy(() -> service.validate("password1234"))
                .isInstanceOf(PasswordPolicyViolation.class)
                .hasMessageContaining("data breach");
    }

    @Test
    @DisplayName("fails open when the breach corpus is unavailable")
    void accepts_whenScreenUnavailable() {
        screenAnswer = BreachedPasswordScreen.Result.UNAVAILABLE;

        assertThatCode(() -> service.validate("correct horse battery staple"))
                .doesNotThrowAnyException();
    }

    @Test
    @DisplayName("does not consult the corpus for a password refused on local rules")
    void skipsScreen_whenLocallyRejected() {
        assertThatThrownBy(() -> service.validate("short"))
                .isInstanceOf(PasswordPolicyViolation.class);
        assertThat(screened).isEmpty();
    }

    // ---- deployments may re-enable composition ------------------------

    @Test
    @DisplayName("re-enabled composition rules report every missing class at once")
    void rejects_missingCharacterClasses_whenReEnabled() {
        props.setRequireUppercase(true);
        props.setRequireDigit(true);
        props.setRequireSymbol(true);

        assertThatThrownBy(() -> service.validate("alllowercase"))
                .isInstanceOf(PasswordPolicyViolation.class)
                .satisfies(e -> {
                    PasswordPolicyViolation v = (PasswordPolicyViolation) e;
                    assertThat(v.getReasons()).contains(
                            "at least one uppercase letter",
                            "at least one digit",
                            "at least one symbol (non-alphanumeric character)");
                });
    }

    @Test
    @DisplayName("rejects a null or empty password without NPE")
    void rejects_nullOrEmpty() {
        assertThatThrownBy(() -> service.validate(null))
                .isInstanceOf(PasswordPolicyViolation.class);
        assertThatThrownBy(() -> service.validate(""))
                .isInstanceOf(PasswordPolicyViolation.class);
    }

    @Test
    @DisplayName("rejects passwords longer than bcrypt's safe 72-byte limit")
    void rejects_tooLong_toAvoidBcryptTruncation() {
        String huge = "Aa1!" + "x".repeat(100);
        assertThatThrownBy(() -> service.validate(huge))
                .isInstanceOf(PasswordPolicyViolation.class)
                .satisfies(e -> {
                    PasswordPolicyViolation v = (PasswordPolicyViolation) e;
                    assertThat(v.getReasons()).anyMatch(r -> r.contains("at most"));
                });
    }

    @Test
    @DisplayName("a lower configured floor lets shorter passwords through")
    void relaxedConfig_allowsShorter() {
        props.setMinLength(6);

        assertThatCode(() -> service.validate("hunter2"))
                .doesNotThrowAnyException();
    }
}
