package tech.cwvermaak.weldforge.service.security;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import tech.cwvermaak.weldforge.model.MfaFactorType;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("AuthenticationMethods — the RFC 8176 amr values a login reports")
class AuthenticationMethodsTest {

    @Nested
    @DisplayName("what the user actually did")
    class Methods {

        @Test
        @DisplayName("a password-only login reports pwd and nothing else")
        void passwordOnly() {
            assertThat(AuthenticationMethods.password()).containsExactly("pwd");
        }

        @Test
        @DisplayName("a password-only login does NOT claim mfa")
        void passwordOnlyIsNotMultiFactor() {
            assertThat(AuthenticationMethods.password()).doesNotContain("mfa");
        }

        @Test
        @DisplayName("password + TOTP reports pwd, otp and mfa")
        void totp() {
            assertThat(AuthenticationMethods.passwordAnd(MfaFactorType.TOTP, false))
                    .containsExactly("pwd", "otp", "mfa");
        }

        @Test
        @DisplayName("password + SMS reports sms, which is not phishing-resistant")
        void sms() {
            assertThat(AuthenticationMethods.passwordAnd(MfaFactorType.SMS, false))
                    .containsExactly("pwd", "sms", "mfa")
                    .doesNotContain("hwk", "swk");
        }

        @Test
        @DisplayName("password + WebAuthn reports hwk — the phishing-resistant factor "
                   + "relying parties gate on")
        void webauthn() {
            assertThat(AuthenticationMethods.passwordAnd(MfaFactorType.WEBAUTHN, false))
                    .containsExactly("pwd", "hwk", "mfa");
        }

        @Test
        @DisplayName("a backup code reports otp regardless of the requested factor type, "
                   + "mirroring MfaService.verifyChallenge taking that path first")
        void backupCodeWins() {
            assertThat(AuthenticationMethods.passwordAnd(MfaFactorType.WEBAUTHN, true))
                    .containsExactly("pwd", "otp", "mfa");
            assertThat(AuthenticationMethods.passwordAnd(null, true))
                    .containsExactly("pwd", "otp", "mfa");
        }

        @Test
        @DisplayName("a null factor with no backup code degrades to otp rather than throwing")
        void nullFactor() {
            assertThat(AuthenticationMethods.passwordAnd(null, false))
                    .containsExactly("pwd", "otp", "mfa");
        }

        @Test
        @DisplayName("no factor maps to a phishing-resistant value by accident")
        void onlyWebauthnIsPhishingResistant() {
            assertThat(AuthenticationMethods.forFactor(MfaFactorType.TOTP)).isEqualTo("otp");
            assertThat(AuthenticationMethods.forFactor(MfaFactorType.SMS)).isEqualTo("sms");
            assertThat(AuthenticationMethods.forFactor(MfaFactorType.WEBAUTHN)).isEqualTo("hwk");
        }
    }

    @Nested
    @DisplayName("storage encoding — the column the grant carries")
    class Storage {

        @Test
        @DisplayName("round-trips through the space-separated column form")
        void roundTrip() {
            List<String> methods = AuthenticationMethods.passwordAnd(MfaFactorType.WEBAUTHN, false);
            String stored = AuthenticationMethods.toStorage(methods);
            assertThat(stored).isEqualTo("pwd hwk mfa");
            assertThat(AuthenticationMethods.fromStorage(stored)).isEqualTo(methods);
        }

        @Test
        @DisplayName("nothing to record stores NULL, not an empty string")
        void emptyStoresNull() {
            assertThat(AuthenticationMethods.toStorage(null)).isNull();
            assertThat(AuthenticationMethods.toStorage(List.of())).isNull();
        }

        @Test
        @DisplayName("a NULL column reads back as no methods, so pre-existing grants "
                   + "assert nothing rather than asserting something false")
        void nullReadsAsEmpty() {
            assertThat(AuthenticationMethods.fromStorage(null)).isEmpty();
            assertThat(AuthenticationMethods.fromStorage("")).isEmpty();
            assertThat(AuthenticationMethods.fromStorage("   ")).isEmpty();
        }

        @Test
        @DisplayName("stray whitespace in a stored value does not produce blank methods")
        void tolerantOfWhitespace() {
            assertThat(AuthenticationMethods.fromStorage("  pwd   hwk  mfa "))
                    .containsExactly("pwd", "hwk", "mfa");
        }
    }
}
