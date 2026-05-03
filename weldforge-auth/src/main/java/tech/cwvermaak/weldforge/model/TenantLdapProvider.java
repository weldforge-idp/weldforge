package tech.cwvermaak.weldforge.model;

import jakarta.persistence.*;
import lombok.*;
import tech.cwvermaak.weldforge.config.crypto.EncryptedStringConverter;

import java.time.LocalDateTime;

/**
 * Per-tenant LDAP / Active Directory upstream provider (PRD DIR-01, DIR-02).
 * The service bind password is encrypted at rest via the shared
 * {@link EncryptedStringConverter}; everything else is plain since URLs
 * and DNs are not secrets.
 */
@Entity
@Table(name = "tenant_ldap_providers")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class TenantLdapProvider {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "tenant_id", nullable = false)
    private Tenant tenant;

    @Column(nullable = false)
    private String name;

    @Enumerated(EnumType.STRING)
    @Column(name = "provider_type", nullable = false, length = 32)
    @Builder.Default
    private LdapProviderType providerType = LdapProviderType.LDAP;

    @Column(nullable = false, length = 1024)
    private String url;

    @Column(name = "bind_dn", length = 512)
    private String bindDn;

    @Convert(converter = EncryptedStringConverter.class)
    @Column(name = "bind_password_enc", columnDefinition = "TEXT")
    private String bindPassword;

    @Column(name = "user_base_dn", nullable = false, length = 512)
    private String userBaseDn;

    @Column(name = "user_search_filter", nullable = false, length = 512)
    @Builder.Default
    private String userSearchFilter = "(uid={0})";

    @Column(name = "email_attribute", nullable = false, length = 64)
    @Builder.Default
    private String emailAttribute = "mail";

    @Column(name = "name_attribute", nullable = false, length = 64)
    @Builder.Default
    private String nameAttribute = "cn";

    @Column(name = "username_attribute", nullable = false, length = 64)
    @Builder.Default
    private String usernameAttribute = "uid";

    @Column(name = "start_tls", nullable = false)
    @Builder.Default
    private boolean startTls = false;

    @Column(name = "connect_timeout_ms", nullable = false)
    @Builder.Default
    private int connectTimeoutMs = 5000;

    @Column(name = "read_timeout_ms", nullable = false)
    @Builder.Default
    private int readTimeoutMs = 10000;

    @Column(nullable = false)
    @Builder.Default
    private boolean enabled = true;

    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @Column(name = "updated_at", nullable = false)
    private LocalDateTime updatedAt;

    @PrePersist
    void onCreate() {
        LocalDateTime now = LocalDateTime.now();
        if (createdAt == null) createdAt = now;
        updatedAt = now;
    }

    @PreUpdate
    void onUpdate() {
        updatedAt = LocalDateTime.now();
    }
}
