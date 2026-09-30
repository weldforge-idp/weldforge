package tech.cwvermaak.weldforge.service;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.time.LocalDateTime;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static tech.cwvermaak.weldforge.service.ServiceAccountExpiry.Intent;
import static tech.cwvermaak.weldforge.service.ServiceAccountExpiry.resolve;

/**
 * Resolving a requested token lifetime.
 *
 * <p>Three states have to stay distinguishable, and collapsing any two of
 * them is what made expiry unusable before: "leave it as it is", "never
 * expire", and "expire at a specific time". With only {@code null} available
 * the first two were the same value, so a token that expired could never be
 * made permanent again.
 */
@DisplayName("Service account token lifetime")
class ServiceAccountExpiryTest {

    private static final LocalDateTime NOW = LocalDateTime.of(2026, 9, 30, 12, 0);

    @Nested
    @DisplayName("the three intents stay distinct")
    class Intents {

        @Test
        @DisplayName("neither field supplied means leave the existing expiry alone")
        void absent_is_unchanged() {
            var r = resolve(null, null, NOW);
            assertThat(r.intent()).isEqualTo(Intent.UNCHANGED);

            LocalDateTime existing = NOW.plusDays(5);
            assertThat(r.applyTo(existing)).isEqualTo(existing);
            assertThat(r.applyTo(null)).isNull();
        }

        @Test
        @DisplayName("zero means never expires, and can clear an existing expiry")
        void zero_is_indefinite() {
            var r = resolve(0, null, NOW);
            assertThat(r.intent()).isEqualTo(Intent.INDEFINITE);
            // The case that was impossible before: a token with an expiry,
            // made permanent again.
            assertThat(r.applyTo(NOW.plusDays(5))).isNull();
        }

        @Test
        @DisplayName("zero in either field, or both, is indefinite")
        void zero_in_any_position() {
            assertThat(resolve(0, null, NOW).intent()).isEqualTo(Intent.INDEFINITE);
            assertThat(resolve(null, 0, NOW).intent()).isEqualTo(Intent.INDEFINITE);
            assertThat(resolve(0, 0, NOW).intent()).isEqualTo(Intent.INDEFINITE);
        }

        @Test
        @DisplayName("a positive duration resolves to an instant")
        void positive_is_absolute() {
            var r = resolve(90, null, NOW);
            assertThat(r.intent()).isEqualTo(Intent.ABSOLUTE);
            assertThat(r.expiresAt()).isEqualTo(NOW.plusDays(90));
            // An explicit request overrides whatever was there.
            assertThat(r.applyTo(NOW.plusYears(1))).isEqualTo(NOW.plusDays(90));
        }
    }

    @Nested
    @DisplayName("days and hours combine")
    class Units {

        @Test
        @DisplayName("hours alone")
        void hours_only() {
            assertThat(resolve(null, 12, NOW).expiresAt()).isEqualTo(NOW.plusHours(12));
        }

        @Test
        @DisplayName("days and hours are summed")
        void days_and_hours() {
            assertThat(resolve(1, 6, NOW).expiresAt()).isEqualTo(NOW.plusDays(1).plusHours(6));
        }

        @Test
        @DisplayName("one hour is a valid, if short, lifetime")
        void one_hour() {
            assertThat(resolve(0, 1, NOW).intent()).isEqualTo(Intent.ABSOLUTE);
            assertThat(resolve(0, 1, NOW).expiresAt()).isEqualTo(NOW.plusHours(1));
        }
    }

    @Nested
    @DisplayName("refused")
    class Refused {

        @Test
        @DisplayName("a negative lifetime, which would issue a token already dead")
        void negative() {
            assertThatThrownBy(() -> resolve(-1, null, NOW))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("cannot be negative")
                    // The message must carry the way to say what they meant.
                    .hasMessageContaining("0");
            assertThatThrownBy(() -> resolve(null, -5, NOW))
                    .isInstanceOf(IllegalArgumentException.class);
        }

        @Test
        @DisplayName("beyond the cap — the transposition guard")
        void implausible() {
            // 87600 is ten years expressed in HOURS, typed into the days box.
            assertThatThrownBy(() -> resolve(87_600, null, NOW))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("3650");
        }

        @Test
        @DisplayName("the cap is reachable in hours too, not just days")
        void cap_applies_to_hours() {
            assertThatThrownBy(() -> resolve(null, ServiceAccountExpiry.MAX_DAYS * 24 + 1, NOW))
                    .isInstanceOf(IllegalArgumentException.class);
        }

        @Test
        @DisplayName("exactly the cap is allowed; one hour past it is not")
        void cap_boundary() {
            assertThat(resolve(ServiceAccountExpiry.MAX_DAYS, null, NOW).intent())
                    .isEqualTo(Intent.ABSOLUTE);
            // The cap is on the total, so days and hours cannot be used to
            // step over it together.
            assertThatThrownBy(() -> resolve(ServiceAccountExpiry.MAX_DAYS, 1, NOW))
                    .isInstanceOf(IllegalArgumentException.class);
        }

        @Test
        @DisplayName("Integer.MAX_VALUE days does not overflow into a valid answer")
        void does_not_overflow() {
            // int arithmetic on hours would wrap and could land under the cap,
            // silently issuing a near-term or past expiry for a huge request.
            assertThatThrownBy(() -> resolve(Integer.MAX_VALUE, null, NOW))
                    .isInstanceOf(IllegalArgumentException.class);
        }
    }

    @Nested
    @DisplayName("describe(), for the audit trail")
    class Describe {

        @Test
        @DisplayName("says plainly when a permanent credential was issued")
        void indefinite_is_named() {
            assertThat(resolve(0, 0, NOW).describe()).isEqualTo("indefinite");
        }

        @Test
        @DisplayName("carries the instant otherwise")
        void absolute_is_timestamped() {
            assertThat(resolve(1, 0, NOW).describe()).isEqualTo(NOW.plusDays(1).toString());
        }
    }
}
