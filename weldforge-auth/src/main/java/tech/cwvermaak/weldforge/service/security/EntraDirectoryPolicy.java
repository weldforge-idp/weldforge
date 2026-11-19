package tech.cwvermaak.weldforge.service.security;

import tech.cwvermaak.weldforge.model.SocialProviderType;

import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * Which Entra ID directories a tenant's Microsoft provider admits (WF-4).
 *
 * <p>A Microsoft app registered as multi-tenant and reached through
 * {@code /common} or {@code /organizations} accepts an account from any
 * directory, and anyone can create a directory. The id token's {@code tid}
 * claim names the directory the account belongs to. It is the Microsoft
 * counterpart of Google's {@code hd}, and like {@code required_hd} an
 * allow-list here demands its presence.
 */
public final class EntraDirectoryPolicy {

    private static final Pattern GUID = Pattern.compile(
            "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}");

    private EntraDirectoryPolicy() {}

    /** The configured ids, lower-cased; empty when nothing is configured. */
    public static Set<String> parse(String raw) {
        if (raw == null || raw.isBlank()) return Set.of();
        return Arrays.stream(raw.trim().split("[\\s,]+"))
                .filter(s -> !s.isBlank())
                .map(s -> s.toLowerCase(Locale.ROOT))
                .collect(Collectors.toCollection(LinkedHashSet::new));
    }

    /** True when no list is configured, or {@code tid} is on it. */
    public static boolean permits(String allowedTids, String tid) {
        Set<String> allowed = parse(allowedTids);
        if (allowed.isEmpty()) return true;
        return tid != null && allowed.contains(tid.trim().toLowerCase(Locale.ROOT));
    }

    /**
     * Validate and canonicalise a value an administrator is storing.
     *
     * @return space-separated lower-case ids, or null for none
     * @throws IllegalArgumentException for a non-Microsoft provider, or a value
     *         that is not a directory id (a domain name is the usual mistake,
     *         and would silently refuse everyone)
     */
    public static String normalise(SocialProviderType provider, String raw) {
        Set<String> ids = parse(raw);
        if (ids.isEmpty()) return null;
        if (provider != SocialProviderType.MICROSOFT) {
            throw new IllegalArgumentException("allowedTids applies only to the MICROSOFT provider");
        }
        for (String id : ids) {
            if (!GUID.matcher(id).matches()) {
                throw new IllegalArgumentException("allowedTids must be Entra ID directory ids (GUIDs), "
                        + "not domain names: '" + id + "'");
            }
        }
        return String.join(" ", ids);
    }
}
