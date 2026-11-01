package tech.cwvermaak.weldforge.service.security;

import java.util.Arrays;
import java.util.List;
import java.util.Set;

/**
 * What a tenant may <em>assert</em> about an upstream provider's
 * authentication, and the one condition under which asserting a
 * phishing-resistant factor means anything.
 *
 * <p>Google returns no {@code amr} claim. Its ID token carries {@code iss},
 * {@code azp}, {@code aud}, {@code sub}, {@code at_hash}, {@code email},
 * {@code email_verified}, {@code name}, {@code picture}, {@code given_name},
 * {@code family_name}, {@code locale}, {@code hd}, {@code iat} and {@code exp}
 * — nothing about how the person authenticated. So WeldForge cannot verify
 * that Google performed MFA; it can only be configured to assert it. That is a
 * legitimate trust decision, and it is how enterprise SSO skips step-up for a
 * trusted upstream, but it is an assertion and this class is named for it.
 *
 * <p>Deliberately a pure function over strings, like {@link
 * tech.cwvermaak.weldforge.service.EmailDomainPolicy}: the rule deciding how
 * strong a federated session may claim to be is worth reading in one place and
 * testing without a database, rather than inferring it from a conditional
 * inside an upsert.
 *
 * <p>The rules, and why each exists:
 *
 * <ul>
 *   <li><b>{@code pwd} is refused outright.</b> No password was presented to
 *       this server. {@code AuthService.issueFederatedSession} has always
 *       refused to claim one, and that refusal is the behaviour being
 *       preserved here, not the one being relaxed.</li>
 *   <li><b>Unknown values are refused</b> rather than stored and silently
 *       never matched by a relying party. A typo that is accepted and does
 *       nothing is worse than a 400.</li>
 *   <li><b>{@code hwk} or {@code swk} requires a hosted-domain gate.</b> See
 *       {@link #requiresHostedDomainGate}.</li>
 * </ul>
 */
public final class AssertedAmrPolicy {

    /**
     * What may be asserted. {@code pwd} is absent on purpose and is refused
     * explicitly below, with its own message, because it is the value somebody
     * will reach for first.
     */
    private static final Set<String> ASSERTABLE = Set.of(
            AuthenticationMethods.OTP,
            AuthenticationMethods.SMS,
            AuthenticationMethods.HARDWARE_KEY,
            AuthenticationMethods.SOFTWARE_KEY,
            AuthenticationMethods.MULTIPLE_FACTOR);

    /**
     * Asserting one of these is a claim of phishing resistance, which is what
     * a vault or a secrets store gates on. KeyCrypt refuses any session whose
     * {@code amr} is disjoint from this set.
     */
    private static final Set<String> PHISHING_RESISTANT = Set.of(
            AuthenticationMethods.HARDWARE_KEY,
            AuthenticationMethods.SOFTWARE_KEY);

    private AssertedAmrPolicy() {
    }

    /** Read the stored space-separated column; null or blank yields an empty list. */
    public static List<String> parse(String stored) {
        if (stored == null || stored.isBlank()) {
            return List.of();
        }
        return Arrays.stream(stored.trim().toLowerCase(java.util.Locale.ROOT).split("\\s+"))
                .filter(v -> !v.isBlank())
                .distinct()
                .toList();
    }

    /**
     * Whether this assertion claims a phishing-resistant factor, and therefore
     * may only be configured alongside a hosted-domain requirement.
     *
     * <p>Two-factor is a property of a Google <em>account</em>, not of the
     * Google provider. Asserting {@code hwk} on a provider asserts it for every
     * person who signs in through it, including one whose account has only a
     * password — a setting that person controls, can switch off, and about
     * which WeldForge is never told.
     *
     * <p>Google sends {@code hd} only for Workspace accounts, naming the hosted
     * domain, and two-factor can be <em>enforced for that domain</em> in
     * Workspace admin where the user cannot turn it off. So an assertion gated
     * on {@code hd} is backed by a policy the operator controls; the same
     * assertion for {@code gmail.com} is backed by nothing.
     */
    public static boolean requiresHostedDomainGate(List<String> asserted) {
        return asserted != null && asserted.stream().anyMatch(PHISHING_RESISTANT::contains);
    }

    /**
     * Validate a provider's configuration, throwing on anything that would
     * store a claim this server cannot stand behind.
     *
     * @param assertedAmr the raw column value, null or blank meaning "assert
     *                    nothing" — always valid, and the default
     * @param requiredHd  the raw hosted-domain requirement, null or blank
     *                    meaning none
     * @throws IllegalArgumentException with a message naming the rule
     */
    public static void validate(String assertedAmr, String requiredHd) {
        List<String> asserted = parse(assertedAmr);
        if (asserted.isEmpty()) {
            return;
        }

        if (asserted.contains(AuthenticationMethods.PASSWORD)) {
            throw new IllegalArgumentException(
                    "assertedAmr must not contain 'pwd': no password is presented to this "
                    + "server on a federated sign-in, so claiming one would make the amr "
                    + "claim a statement about something that did not happen");
        }

        List<String> unknown = asserted.stream().filter(v -> !ASSERTABLE.contains(v)).toList();
        if (!unknown.isEmpty()) {
            throw new IllegalArgumentException(
                    "assertedAmr contains values that are not assertable RFC 8176 methods: "
                    + String.join(", ", unknown) + ". Assertable: "
                    + ASSERTABLE.stream().sorted().toList());
        }

        if (requiresHostedDomainGate(asserted)
                && (requiredHd == null || requiredHd.isBlank())) {
            throw new IllegalArgumentException(
                    "assertedAmr claims a phishing-resistant factor (hwk/swk), which requires "
                    + "requiredHd to be set. Two-factor is a property of a Google account, not "
                    + "of the Google provider: without a hosted-domain gate this would assert "
                    + "phishing resistance for anyone signing in through this provider, "
                    + "including a personal account with only a password. Set requiredHd to a "
                    + "Workspace domain whose 2FA enforcement you control");
        }
    }
}
