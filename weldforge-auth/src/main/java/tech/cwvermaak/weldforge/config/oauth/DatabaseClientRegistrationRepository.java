package tech.cwvermaak.weldforge.config.oauth;

import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.stereotype.Component;
import tech.cwvermaak.weldforge.model.SocialProviderType;
import tech.cwvermaak.weldforge.model.TenantSocialProvider;
import tech.cwvermaak.weldforge.repository.TenantSocialProviderRepository;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.Set;

/**
 * Dynamic, per-tenant {@link ClientRegistrationRepository}. Instead of relying
 * on statically-configured {@code spring.security.oauth2.client.*} properties,
 * this repo looks up {@link TenantSocialProvider} rows at request time and
 * constructs a {@link ClientRegistration} on the fly.
 *
 * Spring Security identifies a client by {@code registrationId}. We encode
 * the tenant and provider into that id as {@code {tenantSlug}-{providerLower}}
 * — e.g. {@code acme-google}. This means a tenant enables Google login by
 * directing users to:
 *
 *   /oauth2/authorization/acme-google
 *
 * and Spring's standard callback path works unchanged:
 *
 *   /login/oauth2/code/acme-google
 *
 * No custom filters or resolver wiring required.
 */
@Component
@RequiredArgsConstructor
public class DatabaseClientRegistrationRepository implements ClientRegistrationRepository {

    private final TenantSocialProviderRepository providerRepository;

    @Override
    public ClientRegistration findByRegistrationId(String registrationId) {
        if (registrationId == null) return null;

        int sep = registrationId.lastIndexOf('-');
        if (sep <= 0 || sep >= registrationId.length() - 1) return null;

        String tenantSlug = registrationId.substring(0, sep);
        String providerName = registrationId.substring(sep + 1).toUpperCase();

        SocialProviderType provider;
        try {
            provider = SocialProviderType.valueOf(providerName);
        } catch (IllegalArgumentException e) {
            return null;
        }

        Optional<TenantSocialProvider> cfg =
                providerRepository.findByTenant_SlugAndProviderAndEnabledTrue(tenantSlug, provider);

        return cfg.map(c -> build(registrationId, c)).orElse(null);
    }

    private ClientRegistration build(String registrationId, TenantSocialProvider cfg) {
        ProviderDefaults defaults = ProviderDefaults.forProvider(cfg.getProvider());
        List<String> scopes = parseScopes(cfg.getScopes(), defaults.defaultScopes());

        ClientRegistration.Builder b = ClientRegistration.withRegistrationId(registrationId)
                .clientId(cfg.getClientId())
                .clientSecret(cfg.getClientSecret())
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
                .scope(scopes)
                .authorizationUri(defaults.authorizationUri())
                .tokenUri(defaults.tokenUri())
                .userInfoUri(defaults.userInfoUri())
                .userNameAttributeName(defaults.userNameAttribute())
                .clientName(cfg.getDisplayName() != null ? cfg.getDisplayName() : defaults.clientName());

        if (defaults.jwkSetUri() != null) {
            b.jwkSetUri(defaults.jwkSetUri());
        }
        if (defaults.issuerUri() != null) {
            b.issuerUri(defaults.issuerUri());
        }
        return b.build();
    }

    private static List<String> parseScopes(String configured, List<String> fallback) {
        if (configured == null || configured.isBlank()) return fallback;
        return Arrays.stream(configured.split("[,\\s]+"))
                .filter(s -> !s.isBlank())
                .toList();
    }

    // -------- Provider endpoint metadata -------------------------------

    /**
     * Endpoint URLs and defaults for each supported provider. Tenants only
     * supply {@code client_id} / {@code client_secret} — the rest is baked in.
     */
    private record ProviderDefaults(
            String clientName,
            String authorizationUri,
            String tokenUri,
            String userInfoUri,
            String jwkSetUri,
            String issuerUri,
            String userNameAttribute,
            List<String> defaultScopes) {

        static ProviderDefaults forProvider(SocialProviderType t) {
            return switch (t) {
                case GOOGLE -> new ProviderDefaults(
                        "Google",
                        "https://accounts.google.com/o/oauth2/v2/auth",
                        "https://www.googleapis.com/oauth2/v4/token",
                        "https://www.googleapis.com/oauth2/v3/userinfo",
                        "https://www.googleapis.com/oauth2/v3/certs",
                        "https://accounts.google.com",
                        "sub",
                        List.of("openid", "profile", "email"));
                case MICROSOFT -> new ProviderDefaults(
                        "Microsoft",
                        "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
                        "https://login.microsoftonline.com/common/oauth2/v2.0/token",
                        "https://graph.microsoft.com/oidc/userinfo",
                        "https://login.microsoftonline.com/common/discovery/v2.0/keys",
                        null,
                        "sub",
                        List.of("openid", "profile", "email"));
                case GITHUB -> new ProviderDefaults(
                        "GitHub",
                        "https://github.com/login/oauth/authorize",
                        "https://github.com/login/oauth/access_token",
                        "https://api.github.com/user",
                        null,
                        null,
                        "id",
                        List.of("read:user", "user:email"));
                case FACEBOOK -> new ProviderDefaults(
                        "Facebook",
                        "https://www.facebook.com/v12.0/dialog/oauth",
                        "https://graph.facebook.com/v12.0/oauth/access_token",
                        "https://graph.facebook.com/me?fields=id,name,email,picture",
                        null,
                        null,
                        "id",
                        List.of("public_profile", "email"));
                case APPLE -> new ProviderDefaults(
                        "Apple",
                        "https://appleid.apple.com/auth/authorize",
                        "https://appleid.apple.com/auth/token",
                        null,
                        "https://appleid.apple.com/auth/keys",
                        "https://appleid.apple.com",
                        "sub",
                        List.of("openid", "name", "email"));
                case LINKEDIN -> new ProviderDefaults(
                        "LinkedIn",
                        "https://www.linkedin.com/oauth/v2/authorization",
                        "https://www.linkedin.com/oauth/v2/accessToken",
                        "https://api.linkedin.com/v2/userinfo",
                        null,
                        null,
                        "sub",
                        List.of("openid", "profile", "email"));
                case TWITTER -> new ProviderDefaults(
                        "Twitter / X",
                        "https://twitter.com/i/oauth2/authorize",
                        "https://api.twitter.com/2/oauth2/token",
                        "https://api.twitter.com/2/users/me",
                        null,
                        null,
                        "id",
                        List.of("tweet.read", "users.read"));
            };
        }
    }

    public static Set<SocialProviderType> supportedProviders() {
        return Set.of(SocialProviderType.values());
    }
}
