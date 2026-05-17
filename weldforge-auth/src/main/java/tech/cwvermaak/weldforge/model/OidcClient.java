package tech.cwvermaak.weldforge.model;

import jakarta.persistence.*;
import lombok.*;
import tech.cwvermaak.weldforge.config.crypto.EncryptedStringConverter;

import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.List;

/**
 * A relying party registered against a tenant. Each tenant has its own
 * client list and its own signing key, so a token issued for tenant A's
 * client cannot be replayed against tenant B's discovery document — the
 * key id won't resolve.
 */
@Entity
@Table(name = "oidc_clients",
       uniqueConstraints = @UniqueConstraint(columnNames = {"tenant_id", "client_id"}))
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class OidcClient {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "tenant_id", nullable = false)
    private Tenant tenant;

    @Column(name = "client_id", nullable = false, length = 128)
    private String clientId;

    @Convert(converter = EncryptedStringConverter.class)
    @Column(name = "client_secret_enc", nullable = false, columnDefinition = "TEXT")
    private String clientSecret;

    private String name;

    /** CSV — see {@link #getRedirectUriList()}. */
    @Column(name = "redirect_uris", nullable = false, columnDefinition = "TEXT")
    private String redirectUris;

    @Column(nullable = false, columnDefinition = "TEXT")
    private String scopes;

    @Column(name = "grant_types", nullable = false, columnDefinition = "TEXT")
    private String grantTypes;

    @Column(name = "require_pkce", nullable = false)
    @Builder.Default
    private Boolean requirePkce = true;

    /** PRD MFA-04 / SSO-05: force a verified factor for every authorize. */
    @Column(name = "require_mfa", nullable = false)
    @Builder.Default
    private Boolean requireMfa = false;

    /**
     * PRD SSO-05: maximum age of the SSO session in seconds before a step-up
     * challenge is required. 0 = no step-up beyond whatever the tenant
     * policy dictates.
     */
    @Column(name = "max_authentication_age_s", nullable = false)
    @Builder.Default
    private Integer maxAuthenticationAgeSeconds = 0;

    /**
     * Browser origins ({@code scheme://host[:port]}) permitted to call this
     * tenant's OIDC endpoints cross-origin. CSV — see {@link #getWebOriginList()}.
     * Feeds the per-tenant CORS allow-list; empty for non-browser clients.
     */
    @Column(name = "web_origins", nullable = false, columnDefinition = "TEXT")
    @Builder.Default
    private String webOrigins = "";

    /**
     * OIDC RP-Initiated Logout {@code post_logout_redirect_uri} allow-list.
     * CSV — see {@link #getPostLogoutRedirectUriList()}. Kept distinct from
     * {@link #redirectUris} because the post-logout landing page is rarely
     * the OAuth callback URL.
     */
    @Column(name = "post_logout_redirect_uris", nullable = false, columnDefinition = "TEXT")
    @Builder.Default
    private String postLogoutRedirectUris = "";

    /**
     * Public client — PKCE-only, no usable client secret at the token
     * endpoint (OAuth 2.1 §2.1, RFC 8252 for native apps). When true,
     * {@link #requirePkce} is forced on and no secret is ever surfaced.
     */
    @Column(name = "public_client", nullable = false)
    @Builder.Default
    private Boolean publicClient = false;

    /** RFC 8414 {@code token_endpoint_auth_method}: {@code client_secret_post} or {@code none}. */
    @Column(name = "token_endpoint_auth_method", nullable = false, length = 32)
    @Builder.Default
    private String tokenEndpointAuthMethod = "client_secret_post";

    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @Column(name = "updated_at", nullable = false)
    private LocalDateTime updatedAt;

    @PrePersist
    void onCreate() {
        LocalDateTime now = LocalDateTime.now();
        if (createdAt == null) createdAt = now;
        updatedAt = now;
        if (requirePkce == null) requirePkce = true;
        if (requireMfa == null) requireMfa = false;
        if (maxAuthenticationAgeSeconds == null) maxAuthenticationAgeSeconds = 0;
        if (webOrigins == null) webOrigins = "";
        if (postLogoutRedirectUris == null) postLogoutRedirectUris = "";
        if (publicClient == null) publicClient = false;
        if (tokenEndpointAuthMethod == null || tokenEndpointAuthMethod.isBlank()) {
            tokenEndpointAuthMethod = "client_secret_post";
        }
        // A public client must use PKCE — there is no secret to fall back on.
        if (Boolean.TRUE.equals(publicClient)) requirePkce = true;
    }

    @PreUpdate
    void onUpdate() {
        updatedAt = LocalDateTime.now();
    }

    public List<String> getRedirectUriList() { return splitCsv(redirectUris); }
    public List<String> getScopeList()       { return splitCsv(scopes); }
    public List<String> getGrantTypeList()   { return splitCsv(grantTypes); }
    public List<String> getWebOriginList()             { return splitCsv(webOrigins); }
    public List<String> getPostLogoutRedirectUriList() { return splitCsv(postLogoutRedirectUris); }

    /** True when this client authenticates with PKCE alone and has no usable secret. */
    public boolean isPublicClient() { return Boolean.TRUE.equals(publicClient); }

    private static List<String> splitCsv(String s) {
        if (s == null || s.isBlank()) return List.of();
        return Arrays.stream(s.split("[,\\s]+"))
                .filter(v -> !v.isBlank())
                .toList();
    }
}
