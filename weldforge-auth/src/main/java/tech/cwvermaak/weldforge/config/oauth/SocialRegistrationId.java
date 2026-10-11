package tech.cwvermaak.weldforge.config.oauth;

import tech.cwvermaak.weldforge.model.SocialProviderType;

import java.util.Locale;
import java.util.Optional;

/**
 * The {@code {tenantSlug}-{provider}} id Spring Security knows a social client
 * by — {@code counteract-studios-google} — and the one place it is taken apart.
 *
 * <p>It was taken apart in three places, and one of them split on the FIRST
 * hyphen while the other two split on the last. A tenant whose slug contains a
 * hyphen therefore authenticated against Google perfectly and then failed at
 * the final step, because the success handler looked up tenant
 * {@code "counteract"} instead of {@code "counteract-studios"} and found no
 * user. Observed in production on 2026-10-11: a 401 whitelabel error page
 * after a successful Google sign-in. Most slugs in use have a hyphen
 * ({@code cwvermaak-tech}, {@code hbc-2s-connect}), so this was close to
 * "social sign-in works for one tenant".
 *
 * <p>Splitting on the last hyphen is the correct rule and is safe: no
 * {@link SocialProviderType} name contains one, so everything before the final
 * hyphen is the slug. That invariant is asserted by a test rather than left as
 * a comment, because adding a provider named {@code SIGN_IN_WITH_APPLE} would
 * quietly break it.
 */
public record SocialRegistrationId(String tenantSlug, SocialProviderType provider) {

    /**
     * @return the parsed id, or empty when it is null, malformed, or names a
     *         provider this build does not support — all of which mean "not a
     *         social registration we own", and never an exception, because
     *         these ids arrive straight off a URL.
     */
    public static Optional<SocialRegistrationId> parse(String registrationId) {
        if (registrationId == null) return Optional.empty();

        int sep = registrationId.lastIndexOf('-');
        if (sep <= 0 || sep >= registrationId.length() - 1) return Optional.empty();

        String slug = registrationId.substring(0, sep);
        String providerName = registrationId.substring(sep + 1).toUpperCase(Locale.ROOT);

        try {
            return Optional.of(new SocialRegistrationId(slug, SocialProviderType.valueOf(providerName)));
        } catch (IllegalArgumentException unknownProvider) {
            return Optional.empty();
        }
    }

    /** The id Spring Security registers this tenant+provider under. */
    public static String of(String tenantSlug, SocialProviderType provider) {
        return tenantSlug + "-" + provider.name().toLowerCase(Locale.ROOT);
    }

    /** Lower-case provider name, as it appears in the id. */
    public String providerKey() {
        return provider.name().toLowerCase(Locale.ROOT);
    }
}
