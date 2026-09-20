package tech.cwvermaak.weldforge.service.security;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import tech.cwvermaak.weldforge.model.Tenant;

import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The resolution table from {@code docs/password-policy-spec.md} §2.
 *
 * <p>The direction that matters is the one a test is least likely to cover:
 * that an override cannot <em>weaken</em> the deployment baseline. A suite that
 * only proved "a stricter tenant is stricter" would pass just as happily
 * against a naive last-write-wins merge, which is the bug this exists to
 * prevent.
 */
@DisplayName("Effective password policy = baseline, tightened by tenant overrides")
class EffectivePasswordPolicyTest {

    /** Baseline mirroring the shipped defaults: 800-63B, no composition rules. */
    private static PasswordPolicyProperties baseline() {
        PasswordPolicyProperties p = new PasswordPolicyProperties();
        p.setMinLength(12);
        p.setMaxLength(72);
        p.setRequireUppercase(false);
        p.setRequireLowercase(false);
        p.setRequireDigit(false);
        p.setRequireSymbol(false);
        return p;
    }

    private static Tenant tenantWith(Map<String, Object> policy) {
        Tenant t = new Tenant();
        t.setPasswordPolicy(policy);
        return t;
    }

    private static Map<String, Object> policy(Object... kv) {
        Map<String, Object> m = new HashMap<>();
        for (int i = 0; i < kv.length; i += 2) m.put((String) kv[i], kv[i + 1]);
        return m;
    }

    @Nested
    @DisplayName("inheritance")
    class Inheritance {

        @Test
        @DisplayName("a null tenant resolves to the baseline")
        void null_tenant_is_baseline() {
            assertThat(EffectivePasswordPolicy.resolve(baseline(), null))
                    .isEqualTo(EffectivePasswordPolicy.baseline(baseline()));
        }

        @Test
        @DisplayName("a tenant with no override resolves to the baseline")
        void no_override_is_baseline() {
            assertThat(EffectivePasswordPolicy.resolve(baseline(), tenantWith(null)))
                    .isEqualTo(EffectivePasswordPolicy.baseline(baseline()));
        }

        @Test
        @DisplayName("an empty override object resolves to the baseline")
        void empty_override_is_baseline() {
            assertThat(EffectivePasswordPolicy.resolve(baseline(), tenantWith(policy())))
                    .isEqualTo(EffectivePasswordPolicy.baseline(baseline()));
        }

        @Test
        @DisplayName("absent keys inherit individually — a partial object is normal")
        void partial_override_inherits_the_rest() {
            EffectivePasswordPolicy r = EffectivePasswordPolicy.resolve(
                    baseline(), tenantWith(policy("minLength", 16)));

            assertThat(r.minLength()).isEqualTo(16);
            // Everything the tenant did not mention still comes from the baseline.
            assertThat(r.maxLength()).isEqualTo(72);
            assertThat(r.requireDigit()).isFalse();
            assertThat(r.requireSymbol()).isFalse();
        }
    }

    @Nested
    @DisplayName("tightening is honoured")
    class Tightening {

        @Test
        @DisplayName("a longer minimum is applied")
        void longer_minimum_applies() {
            assertThat(EffectivePasswordPolicy.resolve(baseline(), tenantWith(policy("minLength", 20)))
                    .minLength()).isEqualTo(20);
        }

        @Test
        @DisplayName("a shorter maximum is applied")
        void shorter_maximum_applies() {
            assertThat(EffectivePasswordPolicy.resolve(baseline(), tenantWith(policy("maxLength", 40)))
                    .maxLength()).isEqualTo(40);
        }

        @Test
        @DisplayName("composition rules can be switched on")
        void composition_rules_can_be_added() {
            EffectivePasswordPolicy r = EffectivePasswordPolicy.resolve(baseline(), tenantWith(
                    policy("requireUppercase", true, "requireDigit", true, "requireSymbol", true)));

            assertThat(r.requireUppercase()).isTrue();
            assertThat(r.requireDigit()).isTrue();
            assertThat(r.requireSymbol()).isTrue();
            assertThat(r.requireLowercase()).isFalse(); // not asked for
        }
    }

    @Nested
    @DisplayName("weakening is refused — the point of the design")
    class Weakening {

        @Test
        @DisplayName("a tenant cannot lower minLength below the baseline")
        void cannot_lower_minimum() {
            assertThat(EffectivePasswordPolicy.resolve(baseline(), tenantWith(policy("minLength", 6)))
                    .minLength())
                    .as("a tenant asking for 6 still gets the baseline's 12")
                    .isEqualTo(12);
        }

        @Test
        @DisplayName("a tenant cannot raise maxLength above the baseline")
        void cannot_raise_maximum() {
            PasswordPolicyProperties b = baseline();
            b.setMaxLength(40);

            assertThat(EffectivePasswordPolicy.resolve(b, tenantWith(policy("maxLength", 72)))
                    .maxLength()).isEqualTo(40);
        }

        @Test
        @DisplayName("a tenant cannot switch off a composition rule the deployment requires")
        void cannot_disable_a_required_rule() {
            PasswordPolicyProperties b = baseline();
            b.setRequireDigit(true);

            assertThat(EffectivePasswordPolicy.resolve(b, tenantWith(policy("requireDigit", false)))
                    .requireDigit())
                    .as("false against a baseline of true is a no-op, not a downgrade")
                    .isTrue();
        }
    }

    @Nested
    @DisplayName("hard bounds survive every layer")
    class Bounds {

        @Test
        @DisplayName("maxLength is capped at bcrypt's 72 bytes even if the baseline asks for more")
        void bcrypt_ceiling_survives_a_misconfigured_baseline() {
            PasswordPolicyProperties b = baseline();
            b.setMaxLength(500);

            assertThat(EffectivePasswordPolicy.baseline(b).maxLength())
                    .as("bcrypt ignores past 72 bytes; a higher limit would silently truncate")
                    .isEqualTo(EffectivePasswordPolicy.BCRYPT_MAX_BYTES);
        }

        @Test
        @DisplayName("a deployment MAY configure a minimum below 800-63B's 8")
        void baseline_minimum_is_not_floored() {
            PasswordPolicyProperties b = baseline();
            b.setMinLength(6);

            // Deliberate. An earlier draft of this class clamped to 8 and broke
            // PasswordPolicyServiceTest.relaxedConfig_allowsShorter, which pins
            // this as intended: a self-hoster owns their own baseline. Tenants
            // are limited relative to their operator, not operators relative to
            // us — and tighten-only already stops a tenant going lower.
            assertThat(EffectivePasswordPolicy.baseline(b).minLength()).isEqualTo(6);
        }

        @Test
        @DisplayName("a minimum above bcrypt's ceiling is capped, or nothing could satisfy it")
        void minimum_cannot_exceed_the_hashable_length() {
            PasswordPolicyProperties b = baseline();
            b.setMinLength(200);

            assertThat(EffectivePasswordPolicy.baseline(b).minLength())
                    .isEqualTo(EffectivePasswordPolicy.BCRYPT_MAX_BYTES);
        }
    }

    @Nested
    @DisplayName("malformed stored values fall back rather than throw")
    class Malformed {

        @Test
        @DisplayName("a non-numeric length is ignored, not fatal")
        void garbage_length_falls_back() {
            // This runs on the login path. Throwing here would deny every
            // registration and reset for the tenant because of one bad cell.
            assertThat(EffectivePasswordPolicy.resolve(baseline(), tenantWith(policy("minLength", "abc")))
                    .minLength()).isEqualTo(12);
        }

        @Test
        @DisplayName("a numeric string is accepted — JSON round-trips are not always Integer")
        void numeric_string_is_read() {
            assertThat(EffectivePasswordPolicy.resolve(baseline(), tenantWith(policy("minLength", "16")))
                    .minLength()).isEqualTo(16);
        }

        @Test
        @DisplayName("a non-integer Number is accepted")
        void double_is_read() {
            assertThat(EffectivePasswordPolicy.resolve(baseline(), tenantWith(policy("minLength", 16.0)))
                    .minLength()).isEqualTo(16);
        }

        @Test
        @DisplayName("an unknown key is ignored at resolution time")
        void unknown_key_is_ignored() {
            // Rejected at write time by PasswordPolicyOverrideValidator; here it
            // must simply not break anything.
            assertThat(EffectivePasswordPolicy.resolve(baseline(), tenantWith(policy("minlength", 20)))
                    .minLength()).isEqualTo(12);
        }
    }

    @Nested
    @DisplayName("breach screening is deployment-wide, not tenant-configurable")
    class BreachScreening {

        @Test
        @DisplayName("a tenant cannot switch breach screening off")
        void tenant_cannot_disable() {
            assertThat(EffectivePasswordPolicy.resolve(
                    baseline(), tenantWith(policy("breachCheckEnabled", false))).breachCheckEnabled())
                    .isTrue();
        }

        @Test
        @DisplayName("a tenant cannot switch it on for an air-gapped deployment")
        void tenant_cannot_enable() {
            PasswordPolicyProperties b = baseline();
            b.getBreachCheck().setEnabled(false);

            // The injected screen is a no-op stub when disabled, so honouring
            // this would change nothing while appearing to — and the flag exists
            // so an air-gapped deployment makes no outbound calls.
            assertThat(EffectivePasswordPolicy.resolve(
                    b, tenantWith(policy("breachCheckEnabled", true))).breachCheckEnabled())
                    .isFalse();
        }
    }
}
