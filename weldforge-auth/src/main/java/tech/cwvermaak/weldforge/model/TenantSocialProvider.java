package tech.cwvermaak.weldforge.model;

import jakarta.persistence.*;
import lombok.*;
import tech.cwvermaak.weldforge.config.crypto.EncryptedStringConverter;

import java.time.LocalDateTime;

/**
 * Per-tenant configuration for a single social identity provider
 * (Google, Microsoft, GitHub, ...). The client secret is encrypted
 * at rest via {@link EncryptedStringConverter}.
 */
@Entity
@Table(name = "tenant_social_providers",
       uniqueConstraints = @UniqueConstraint(columnNames = {"tenant_id", "provider"}))
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class TenantSocialProvider {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "tenant_id", nullable = false)
    private Tenant tenant;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 32)
    private SocialProviderType provider;

    @Column(name = "display_name", length = 128)
    private String displayName;

    @Column(name = "client_id", nullable = false, length = 512)
    private String clientId;

    /** Encrypted at rest (AES-GCM via EncryptedStringConverter). */
    @Convert(converter = EncryptedStringConverter.class)
    @Column(name = "client_secret_enc", nullable = false, columnDefinition = "TEXT")
    private String clientSecret;

    /** Comma-separated scope overrides. When null/blank, provider defaults are used. */
    @Column(length = 512)
    private String scopes;

    @Column(nullable = false)
    @Builder.Default
    private Boolean enabled = true;

    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @Column(name = "updated_at", nullable = false)
    private LocalDateTime updatedAt;

    @PrePersist
    void onCreate() {
        LocalDateTime now = LocalDateTime.now();
        if (createdAt == null) createdAt = now;
        updatedAt = now;
        if (enabled == null) enabled = true;
    }

    @PreUpdate
    void onUpdate() {
        updatedAt = LocalDateTime.now();
    }
}
