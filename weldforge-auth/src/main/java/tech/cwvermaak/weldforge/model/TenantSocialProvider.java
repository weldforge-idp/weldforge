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

    /**
     * Space-separated RFC 8176 methods <em>asserted</em> for sessions from this
     * provider, or null to assert nothing (the default, and every pre-V71 row).
     *
     * <p>Asserted, never verified. Google returns no {@code amr} claim, so this
     * records a trust decision an operator took about an upstream — not an
     * observation of what the person did. Never contains {@code pwd}: no
     * password is presented to this server.
     */
    @Column(name = "asserted_amr", length = 128)
    private String assertedAmr;

    /**
     * Space-separated hosted domains (Google's {@code hd}) required of a
     * sign-in through this provider, or null for no requirement.
     *
     * <p>This is what makes {@link #assertedAmr} worth anything: two-factor is
     * a property of a Google <em>account</em>, not of the provider, but it can
     * be enforced for a Workspace <em>domain</em>, where the user cannot switch
     * it off. Mandatory whenever {@code assertedAmr} claims a
     * phishing-resistant factor.
     *
     * <p>Distinct from {@code Tenant.allowedEmailDomains}, which permits a
     * sign-in when {@code hd} is absent. This one demands presence.
     */
    @Column(name = "required_hd", length = 255)
    private String requiredHd;

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
