package tech.cwvermaak.intellisso.model;

import jakarta.persistence.*;
import lombok.*;
import tech.cwvermaak.intellisso.config.crypto.EncryptedStringConverter;

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
    }

    @PreUpdate
    void onUpdate() {
        updatedAt = LocalDateTime.now();
    }

    public List<String> getRedirectUriList() { return splitCsv(redirectUris); }
    public List<String> getScopeList()       { return splitCsv(scopes); }
    public List<String> getGrantTypeList()   { return splitCsv(grantTypes); }

    private static List<String> splitCsv(String s) {
        if (s == null || s.isBlank()) return List.of();
        return Arrays.stream(s.split("[,\\s]+"))
                .filter(v -> !v.isBlank())
                .toList();
    }
}
