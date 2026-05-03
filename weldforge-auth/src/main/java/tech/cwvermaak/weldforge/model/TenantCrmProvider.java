package tech.cwvermaak.weldforge.model;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;
import tech.cwvermaak.weldforge.config.crypto.EncryptedStringConverter;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

/**
 * Per-tenant CRM connector config (PRD §3.10). Encapsulates which CRM
 * to push to, how to authenticate, which fields to send, and how to
 * de-duplicate against an existing record.
 *
 * <p>field_mappings is an ordered list of {@code {source, target}}
 * entries where {@code source} is a WeldForge user attribute
 * ({@code email}, {@code name}, {@code roles}, {@code custom.<key>}) and
 * {@code target} is the CRM field name. {@code match_keys} lists the
 * WeldForge source attributes whose values should be compared against
 * the stored log for dedupe.
 */
@Entity
@Table(name = "tenant_crm_providers")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class TenantCrmProvider {

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
    private CrmProviderType providerType;

    @Column(name = "base_url", nullable = false, length = 1024)
    private String baseUrl;

    @Convert(converter = EncryptedStringConverter.class)
    @Column(name = "api_token_enc", nullable = false, columnDefinition = "TEXT")
    private String apiToken;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "field_mappings", columnDefinition = "jsonb", nullable = false)
    private List<Map<String, Object>> fieldMappings;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "match_keys", columnDefinition = "jsonb")
    private List<String> matchKeys;

    @Column(nullable = false)
    @Builder.Default
    private boolean enabled = true;

    @Column(name = "dedupe_enabled", nullable = false)
    @Builder.Default
    private boolean dedupeEnabled = true;

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
