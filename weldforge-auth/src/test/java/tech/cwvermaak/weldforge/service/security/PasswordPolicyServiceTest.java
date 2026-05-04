package tech.cwvermaak.weldforge.service.security;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class PasswordPolicyServiceTest {

    private PasswordPolicyProperties props;
    private PasswordPolicyService service;

    @BeforeEach
    void setUp() {
        props = new PasswordPolicyProperties();
        service = new PasswordPolicyService(props);
    }

    @Test
    @DisplayName("accepts a password that meets every requirement")
    void accepts_strongPassword() {
        assertThatCode(() -> service.validate("Correct-Horse-9"))
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
    @DisplayName("rejects missing character classes and returns every reason at once")
    void rejects_missingCharacterClasses() {
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
    @DisplayName("relaxing the config lets previously-rejected passwords through")
    void relaxedConfig_allowsSimpler() {
        props.setRequireUppercase(false);
        props.setRequireDigit(false);
        props.setRequireSymbol(false);
        props.setMinLength(6);

        assertThatCode(() -> service.validate("hunter2"))
                .doesNotThrowAnyException();
    }
}
