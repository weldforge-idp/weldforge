package tech.cwvermaak.weldforge.service;

import java.util.Arrays;
import java.util.List;
import java.util.Locale;

/**
 * Which email domains may sign in to a tenant.
 *
 * <p>A tenant federated to Google Workspace accepts <em>any</em> Google
 * account unless something says otherwise. The sign-in URL is the only thing
 * standing between a stranger's personal address and the tenant, and a URL is
 * not an access control.
 *
 * <p>Deliberately a pure function over strings. The decision of who may enter
 * a tenant is worth being able to read in one place and test without a
 * database, rather than inferring it from a conditional inside a provisioning
 * callback.
 */
public final class EmailDomainPolicy {

    private EmailDomainPolicy() {
    }

    /** Parse the stored space-separated list; null or blank yields none. */
    public static List<String> parse(String stored) {
        if (stored == null || stored.isBlank()) return List.of();
        return Arrays.stream(stored.trim().toLowerCase(Locale.ROOT).split("\\s+"))
                .map(EmailDomainPolicy::normalise)
                .filter(d -> !d.isBlank())
                .distinct()
                .toList();
    }

    /**
     * Tolerate the shapes an administrator actually types: a bare domain,
     * {@code @example.com}, or a stray leading dot. Storing what they meant
     * beats refusing a form over an {@code @}.
     */
    private static String normalise(String raw) {
        String d = raw.trim().toLowerCase(Locale.ROOT);
        if (d.startsWith("@")) d = d.substring(1);
        if (d.startsWith(".")) d = d.substring(1);
        return d;
    }

    /** The part after the last {@code @}, lower-cased; null when there isn't one. */
    public static String domainOf(String email) {
        if (email == null) return null;
        int at = email.lastIndexOf('@');
        if (at < 0 || at == email.length() - 1) return null;
        return email.substring(at + 1).trim().toLowerCase(Locale.ROOT);
    }

    /**
     * Whether this sign-in is permitted.
     *
     * @param allowed       the tenant's list; empty means unrestricted
     * @param email         the address being signed in
     * @param hostedDomain  the provider's asserted organisation — Google's
     *                      {@code hd} — or null. When present it must ALSO be
     *                      allowed: a Workspace account can carry an address
     *                      in one domain while belonging to another, and the
     *                      organisation is the thing being admitted.
     */
    public static boolean permits(List<String> allowed, String email, String hostedDomain) {
        if (allowed == null || allowed.isEmpty()) return true;

        String emailDomain = domainOf(email);
        if (emailDomain == null) return false;
        if (!matches(allowed, emailDomain)) return false;

        if (hostedDomain != null && !hostedDomain.isBlank()) {
            return matches(allowed, normalise(hostedDomain));
        }
        return true;
    }

    /**
     * Exact match, or a subdomain of an allowed domain.
     *
     * <p>{@code example.com} admits {@code eu.example.com}. It does NOT admit
     * {@code notexample.com} — the dot is what makes the suffix a boundary
     * rather than a string, and omitting it is how an allow-list ends up
     * admitting an attacker-registered lookalike.
     */
    private static boolean matches(List<String> allowed, String candidate) {
        for (String d : allowed) {
            if (candidate.equals(d)) return true;
            if (candidate.endsWith("." + d)) return true;
        }
        return false;
    }
}
