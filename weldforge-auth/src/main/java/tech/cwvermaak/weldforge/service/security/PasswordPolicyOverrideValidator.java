package tech.cwvermaak.weldforge.service.security;

import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Validates a tenant's {@code password_policy} override <em>at write time</em>,
 * so an administrator saving nonsense is told immediately rather than
 * discovering it when their users cannot register.
 *
 * <p>The division of labour with {@link EffectivePasswordPolicy} is deliberate:
 *
 * <ul>
 *   <li><strong>Here (write path):</strong> reject what is malformed or
 *       out of range — a negative length, a {@code maxLength} above bcrypt's
 *       72-byte ceiling, an unrecognised key, a non-numeric length. A person is
 *       present to read the error.</li>
 *   <li><strong>There (login path):</strong> never throw. A bad value that
 *       somehow reached the column falls back to the baseline, because denying
 *       every login for a tenant is a worse failure than ignoring one
 *       setting.</li>
 * </ul>
 *
 * <p>Note what is <em>not</em> rejected: a value that is merely weaker than the
 * deployment baseline. That is a legitimate thing to store — the baseline may
 * later relax, at which point the tenant's value starts to apply — and it is
 * surfaced in the admin UI as "overridden by the deployment baseline" rather
 * than refused. Refusing it would make the policy depend on the order in which
 * two independent settings were edited.
 */
@Component
public class PasswordPolicyOverrideValidator {

    private static final Set<String> KNOWN_KEYS = Set.of(
            EffectivePasswordPolicy.K_MIN_LENGTH,
            EffectivePasswordPolicy.K_MAX_LENGTH,
            EffectivePasswordPolicy.K_UPPERCASE,
            EffectivePasswordPolicy.K_LOWERCASE,
            EffectivePasswordPolicy.K_DIGIT,
            EffectivePasswordPolicy.K_SYMBOL);

    private static final Set<String> BOOLEAN_KEYS = Set.of(
            EffectivePasswordPolicy.K_UPPERCASE,
            EffectivePasswordPolicy.K_LOWERCASE,
            EffectivePasswordPolicy.K_DIGIT,
            EffectivePasswordPolicy.K_SYMBOL);

    /**
     * @throws PasswordPolicyViolation with every reason at once — an
     *         administrator fixing one field at a time across three round-trips
     *         is a worse experience than one list.
     */
    public void validate(Map<String, Object> override) {
        if (override == null || override.isEmpty()) {
            return; // null means inherit, and is always valid.
        }

        List<String> reasons = new ArrayList<>();

        for (String key : override.keySet()) {
            if (!KNOWN_KEYS.contains(key)) {
                // Named explicitly: a silently-ignored typo ("minlength") looks
                // exactly like a policy that saved and did nothing.
                reasons.add("unknown password policy key '" + key + "'; expected one of " + sorted());
            }
        }

        Integer min = requireInt(override, EffectivePasswordPolicy.K_MIN_LENGTH, reasons);
        Integer max = requireInt(override, EffectivePasswordPolicy.K_MAX_LENGTH, reasons);

        // Lower bound is 1, not 800-63B's 8: a self-hosted deployment may run a
        // baseline beneath 8, and refusing a tenant value between the two would
        // reject something stricter than what the deployment already allows.
        // Overrides can only tighten, so a weak number here is inert anyway.
        if (min != null && (min < 1 || min > EffectivePasswordPolicy.BCRYPT_MAX_BYTES)) {
            reasons.add("minLength must be between 1 and " + EffectivePasswordPolicy.BCRYPT_MAX_BYTES);
        }
        if (max != null && (max < 1 || max > EffectivePasswordPolicy.BCRYPT_MAX_BYTES)) {
            // Not clamped silently: a tenant told nothing would believe it had
            // allowed 200-character passwords when bcrypt ignores past 72.
            reasons.add("maxLength must be between 1 and " + EffectivePasswordPolicy.BCRYPT_MAX_BYTES
                    + " (bcrypt hashes only the first " + EffectivePasswordPolicy.BCRYPT_MAX_BYTES + " bytes)");
        }
        if (min != null && max != null && min > max) {
            reasons.add("minLength (" + min + ") must not exceed maxLength (" + max + ")");
        }

        for (String key : BOOLEAN_KEYS) {
            Object v = override.get(key);
            if (v != null && !(v instanceof Boolean) && !isBooleanString(v)) {
                reasons.add(key + " must be true or false");
            }
        }

        if (!reasons.isEmpty()) {
            throw new PasswordPolicyViolation(reasons);
        }
    }

    private static Integer requireInt(Map<String, Object> o, String key, List<String> reasons) {
        Object v = o.get(key);
        if (v == null) return null;
        if (v instanceof Number n) return n.intValue();
        if (v instanceof String s) {
            try {
                return Integer.parseInt(s.trim());
            } catch (NumberFormatException ignored) {
                reasons.add(key + " must be a whole number");
                return null;
            }
        }
        reasons.add(key + " must be a whole number");
        return null;
    }

    private static boolean isBooleanString(Object v) {
        if (!(v instanceof String s)) return false;
        String t = s.trim();
        return "true".equalsIgnoreCase(t) || "false".equalsIgnoreCase(t);
    }

    private static String sorted() {
        return KNOWN_KEYS.stream().sorted().toList().toString();
    }
}
