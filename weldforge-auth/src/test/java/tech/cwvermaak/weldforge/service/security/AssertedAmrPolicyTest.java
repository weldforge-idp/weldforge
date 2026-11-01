package tech.cwvermaak.weldforge.service.security;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * The rule deciding how strong a federated session may claim to be.
 *
 * <p>Google returns no {@code amr} claim, so a tenant enabling this is
 * asserting rather than observing. Every case below is a way that assertion
 * could become a claim this server cannot stand behind.
 */
@DisplayName("Asserted amr policy")
class AssertedAmrPolicyTest {

    @Nested
    @DisplayName("asserting nothing")
    class AssertingNothing {

        @ParameterizedTest
        @ValueSource(strings = {"", "   "})
        @DisplayName("blank is valid and is what every pre-V71 row holds")
        void blankIsValid(String value) {
            assertThatCode(() -> AssertedAmrPolicy.validate(value, null)).doesNotThrowAnyException();
            assertThat(AssertedAmrPolicy.parse(value)).isEmpty();
        }

        @Test
        @DisplayName("null is valid, and is the column default")
        void nullIsValid() {
            assertThatCode(() -> AssertedAmrPolicy.validate(null, null)).doesNotThrowAnyException();
            assertThat(AssertedAmrPolicy.parse(null)).isEmpty();
        }
    }

    @Nested
    @DisplayName("pwd")
    class Password {

        @Test
        @DisplayName("is refused: no password was presented to this server")
        void pwdRefused() {
            assertThatThrownBy(() -> AssertedAmrPolicy.validate("pwd", null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("pwd");
        }

        @Test
        @DisplayName("is refused even alongside a legitimate value")
        void pwdRefusedInCombination() {
            assertThatThrownBy(() -> AssertedAmrPolicy.validate("pwd otp", null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("pwd");
        }
    }

    @Nested
    @DisplayName("unknown values")
    class Unknown {

        @ParameterizedTest
        @ValueSource(strings = {"federated", "google", "sso", "hwk2", "mfa!"})
        @DisplayName("are refused rather than stored and silently never matched")
        void unknownRefused(String value) {
            assertThatThrownBy(() -> AssertedAmrPolicy.validate(value, "example.com"))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("not assertable");
        }

        @Test
        @DisplayName("'federated' in particular: RFC 8176 has no such value")
        void federatedIsNotARegisteredValue() {
            assertThatThrownBy(() -> AssertedAmrPolicy.validate("federated", "example.com"))
                    .isInstanceOf(IllegalArgumentException.class);
        }
    }

    @Nested
    @DisplayName("the hosted-domain gate")
    class HostedDomainGate {

        @ParameterizedTest
        @ValueSource(strings = {"hwk", "swk", "hwk mfa", "otp swk"})
        @DisplayName("a phishing-resistant assertion without requiredHd is refused")
        void phishingResistantNeedsGate(String value) {
            assertThatThrownBy(() -> AssertedAmrPolicy.validate(value, null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("requiredHd");
        }

        @Test
        @DisplayName("blank requiredHd is no gate at all")
        void blankIsNoGate() {
            assertThatThrownBy(() -> AssertedAmrPolicy.validate("hwk", "   "))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("requiredHd");
        }

        @Test
        @DisplayName("with requiredHd set, it is accepted")
        void gatedIsAccepted() {
            assertThatCode(() -> AssertedAmrPolicy.validate("hwk mfa", "cwvermaak.tech"))
                    .doesNotThrowAnyException();
        }

        @Test
        @DisplayName("a non-phishing-resistant assertion needs no gate")
        void otpNeedsNoGate() {
            assertThatCode(() -> AssertedAmrPolicy.validate("otp mfa", null))
                    .doesNotThrowAnyException();
            assertThat(AssertedAmrPolicy.requiresHostedDomainGate(AssertedAmrPolicy.parse("otp mfa")))
                    .isFalse();
        }

        @Test
        @DisplayName("hwk and swk are the values that demand it")
        void whichValuesDemandIt() {
            assertThat(AssertedAmrPolicy.requiresHostedDomainGate(AssertedAmrPolicy.parse("hwk"))).isTrue();
            assertThat(AssertedAmrPolicy.requiresHostedDomainGate(AssertedAmrPolicy.parse("swk"))).isTrue();
            assertThat(AssertedAmrPolicy.requiresHostedDomainGate(AssertedAmrPolicy.parse("sms"))).isFalse();
        }
    }

    @Nested
    @DisplayName("parsing")
    class Parsing {

        @Test
        @DisplayName("space-separated, lower-cased, de-duplicated")
        void parses() {
            assertThat(AssertedAmrPolicy.parse("  HWK   mfa hwk ")).containsExactly("hwk", "mfa");
        }

        @Test
        @DisplayName("case does not let an unknown value through")
        void caseInsensitiveValidation() {
            assertThatThrownBy(() -> AssertedAmrPolicy.validate("PWD", null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("pwd");
        }
    }
}
