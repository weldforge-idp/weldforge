package tech.cwvermaak.weldforge.service.security;

import tech.cwvermaak.weldforge.model.Tenant;

import java.util.Map;

/**
 * The password rules actually applied to one request: the deployment baseline
 * ({@link PasswordPolicyProperties}) with a tenant's overrides layered on top.
 *
 * <p>Immutable and computed per call. It is deliberately not cached: the
 * baseline is a singleton bean and the tenant is already loaded by the caller,
 * so resolution is a handful of comparisons — cheaper than the invalidation
 * bug that a cache keyed on a mutable tenant row would eventually produce.
 *
 * <p><strong>Overrides may only tighten.</strong> A tenant cannot lower
 * {@code minLength}, cannot raise {@code maxLength}, and cannot switch off a
 * composition rule or breach screening that the deployment has switched on.
 * The reasoning is in {@code docs/password-policy-spec.md} §2; the short
 * version is that the people affected are the tenant's end users, who never
 * chose the policy, and the operator is answerable for them.
 *
 * <p>A weakening value is a <em>no-op</em>, not a rejection — the admin UI
 * shows the effective result beside the override so it is visible rather than
 * silent (spec §6). Values that are nonsensical rather than merely weak
 * (a negative length, a {@code maxLength} above bcrypt's 72-byte ceiling) are
 * refused at write time instead; see {@link PasswordPolicyOverrideValidator}.
 *
 * <p><strong>Breach screening is deployment-wide and NOT tenant-configurable.</strong>
 * Two reasons, both found while implementing rather than while specifying:
 * when {@code app.security.password.breach-check.enabled=false} the injected
 * {@link BreachedPasswordScreen} is a no-op stub, so a tenant switching it on
 * would change nothing while appearing to; and that flag exists for air-gapped
 * deployments, so honouring a tenant's request to enable it would let a tenant
 * force outbound network calls the operator deliberately switched off. A tenant
 * cannot weaken it either — it simply always follows the baseline.
 */
public record EffectivePasswordPolicy(
        int minLength,
        int maxLength,
        boolean requireUppercase,
        boolean requireLowercase,
        boolean requireDigit,
        boolean requireSymbol,
        boolean breachCheckEnabled
) {

    /** Keys recognised in the tenant's {@code password_policy} JSONB. */
    public static final String K_MIN_LENGTH   = "minLength";
    public static final String K_MAX_LENGTH   = "maxLength";
    public static final String K_UPPERCASE    = "requireUppercase";
    public static final String K_LOWERCASE    = "requireLowercase";
    public static final String K_DIGIT        = "requireDigit";
    public static final String K_SYMBOL       = "requireSymbol";

    /**
     * bcrypt hashes only the first 72 bytes. A longer limit would silently
     * ignore the tail, so this ceiling survives every layer of configuration —
     * baseline and tenant alike.
     */
    public static final int BCRYPT_MAX_BYTES = 72;

    /**
     * NIST SP 800-63B's own floor, used as the <em>recommended</em> lower bound
     * when an administrator types a tenant override.
     *
     * <p>Deliberately NOT enforced against the deployment baseline. A
     * self-hosted operator owns {@code app.security.password.min-length} and may
     * set it lower; {@code PasswordPolicyServiceTest.relaxedConfig_allowsShorter}
     * pins that as intended behaviour. Clamping it here would have quietly taken
     * away a capability nobody asked to remove, which is the opposite of the
     * boundary this feature is about — tenants are limited relative to their
     * operator, not operators relative to us.
     *
     * <p>No floor is needed on the resolution path regardless: overrides may
     * only tighten, so a tenant can never land beneath the baseline.
     */
    public static final int RECOMMENDED_MIN_LENGTH = 8;

    /** The deployment baseline with no tenant layered on. */
    public static EffectivePasswordPolicy baseline(PasswordPolicyProperties p) {
        return new EffectivePasswordPolicy(
                clampMin(p.getMinLength()),
                clampMax(p.getMaxLength()),
                p.isRequireUppercase(),
                p.isRequireLowercase(),
                p.isRequireDigit(),
                p.isRequireSymbol(),
                p.getBreachCheck().isEnabled());
    }

    /**
     * Baseline with {@code tenant}'s overrides applied. A null tenant, or one
     * with no {@code passwordPolicy}, yields the baseline unchanged.
     */
    public static EffectivePasswordPolicy resolve(PasswordPolicyProperties p, Tenant tenant) {
        EffectivePasswordPolicy base = baseline(p);
        Map<String, Object> o = tenant == null ? null : tenant.getPasswordPolicy();
        if (o == null || o.isEmpty()) {
            return base;
        }
        return new EffectivePasswordPolicy(
                // Tighten only: a tenant may raise the floor, never lower it.
                Math.max(base.minLength(), clampMin(intOr(o, K_MIN_LENGTH, base.minLength()))),
                // ...and lower the ceiling, never raise it.
                Math.min(base.maxLength(), clampMax(intOr(o, K_MAX_LENGTH, base.maxLength()))),
                base.requireUppercase() || boolOr(o, K_UPPERCASE, false),
                base.requireLowercase() || boolOr(o, K_LOWERCASE, false),
                base.requireDigit()     || boolOr(o, K_DIGIT,     false),
                base.requireSymbol()    || boolOr(o, K_SYMBOL,    false),
                // Deliberately NOT tenant-configurable — see the class javadoc.
                base.breachCheckEnabled());
    }

    /**
     * Only an upper bound. A deployment may configure a minimum as low as it
     * likes — see {@link #RECOMMENDED_MIN_LENGTH} — but never one above the
     * length bcrypt can actually hash, which would make every password
     * unsatisfiable.
     */
    private static int clampMin(int v) {
        return Math.min(v, BCRYPT_MAX_BYTES);
    }

    /**
     * bcrypt hashes only the first 72 bytes, so a higher ceiling would accept a
     * password and silently ignore its tail. Capped rather than trusted.
     */
    private static int clampMax(int v) {
        return Math.min(v, BCRYPT_MAX_BYTES);
    }

    /**
     * JSONB round-trips integers as Integer, but a hand-edited value or a
     * client sending {@code 14.0} arrives as another Number, and a value typed
     * into a form may arrive as a String. Anything uninterpretable falls back
     * to the baseline rather than throwing: this runs on the login path, and a
     * malformed override must not deny every user of the tenant. The write-time
     * validator is what rejects bad input, where a human is present to read it.
     */
    private static int intOr(Map<String, Object> o, String key, int fallback) {
        Object v = o.get(key);
        if (v instanceof Number n) return n.intValue();
        if (v instanceof String s) {
            try {
                return Integer.parseInt(s.trim());
            } catch (NumberFormatException ignored) {
                return fallback;
            }
        }
        return fallback;
    }

    private static boolean boolOr(Map<String, Object> o, String key, boolean fallback) {
        Object v = o.get(key);
        if (v instanceof Boolean b) return b;
        if (v instanceof String s)  return Boolean.parseBoolean(s.trim());
        return fallback;
    }
}
