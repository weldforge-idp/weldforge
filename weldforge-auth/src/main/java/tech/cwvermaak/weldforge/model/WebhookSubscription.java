package tech.cwvermaak.weldforge.model;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;
import tech.cwvermaak.weldforge.config.crypto.EncryptedStringConverter;

import java.time.LocalDateTime;
import java.util.List;

/**
 * Per-tenant webhook subscription (PRD API-05, API-06, SSO-09).
 *
 * <p>A subscription carries the target URL, an HMAC secret used to sign
 * every outbound body, and an optional list of event-type glob filters
 * (e.g. {@code "user.*"}, {@code "auth.login.*"}). The secret is encrypted
 * at rest via the shared {@link EncryptedStringConverter}.
 */
@Entity
@Table(name = "webhook_subscriptions")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class WebhookSubscription {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "tenant_id", nullable = false)
    private Tenant tenant;

    @Column(nullable = false)
    private String name;

    @Column(name = "target_url", nullable = false, length = 2048)
    private String targetUrl;

    @Convert(converter = EncryptedStringConverter.class)
    @Column(name = "secret_enc", nullable = false, columnDefinition = "TEXT")
    private String secret;

    /**
     * Ordered list of glob filters. NULL / empty means "subscribe to all
     * events". Matching is done by {@link tech.cwvermaak.weldforge.service.webhook.WebhookPublisher}.
     */
    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "event_filters", columnDefinition = "jsonb")
    private List<String> eventFilters;

    @Column(nullable = false)
    @Builder.Default
    private boolean enabled = true;

    @Column(name = "max_attempts", nullable = false)
    @Builder.Default
    private int maxAttempts = 6;

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
