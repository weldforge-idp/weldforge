package tech.cwvermaak.intellisso.model;

/**
 * Supported per-tenant social identity providers. Endpoint metadata and
 * default scopes for each provider live in DatabaseClientRegistrationRepository
 * so that tenants only need to supply client_id / client_secret (plus optional
 * scope overrides) when enabling a provider.
 */
public enum SocialProviderType {
    GOOGLE,
    MICROSOFT,
    GITHUB,
    FACEBOOK,
    APPLE,
    LINKEDIN,
    TWITTER
}
