package tech.cwvermaak.weldforge.model;

public enum AuthProvider {
    LOCAL,
    // OAuth2 / social
    GOOGLE, GITHUB, FACEBOOK, AZURE, MICROSOFT, APPLE, TWITTER, LINKEDIN, AMAZON, INSTAGRAM, TIKTOK,
    // Federated
    SAML,
    LDAP
}
