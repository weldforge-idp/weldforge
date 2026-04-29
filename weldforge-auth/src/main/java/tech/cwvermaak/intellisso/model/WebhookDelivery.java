package tech.cwvermaak.intellisso.model;

import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;

/**
 * A single attempted delivery of an event to a {@link WebhookSubscription}.
 * The row is the source of truth for retry scheduling: the background
 * retry job scans by {@code (status, next_attempt_at)}.
 *
 * <p>State machine: {@code PENDING} → {@code SUCCESS} on 2xx, or
 * {@code PENDING} → {@code PENDING} (with {@code next_attempt_at} bumped
 * by exponential backoff) on retryable failure, or
 * {@code PENDING} → {@code DEAD_LETTER} once {@code attempt_count} reaches
 * the subscription's {@code max_attempts}. {@code FAILED} is reserved for
 * non-retryable failures (e.g. 4xx responses).
 */
@Entity
@Table(name = "webhook_deliveries")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class WebhookDelivery {

    public enum Status { PENDING, SUCCESS, FAILED, DEAD_LETTER }

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "subscription_id", nullable = false)
    private WebhookSubscription subscription;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "tenant_id", nullable = false)
    private Tenant tenant;

    @Column(name = "event_type", nullable = false, length = 128)
    private String eventType;

    @Column(name = "event_id", nullable = false, length = 64)
    private String eventId;

    @Column(name = "payload_json", nullable = false, columnDefinition = "TEXT")
    private String payloadJson;

    @Column(nullable = false, length = 128)
    private String signature;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 32)
    @Builder.Default
    private Status status = Status.PENDING;

    @Column(name = "attempt_count", nullable = false)
    @Builder.Default
    private int attemptCount = 0;

    @Column(name = "last_response_code")
    private Integer lastResponseCode;

    @Column(name = "last_error", columnDefinition = "TEXT")
    private String lastError;

    @Column(name = "next_attempt_at")
    private LocalDateTime nextAttemptAt;

    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @Column(name = "delivered_at")
    private LocalDateTime deliveredAt;

    @PrePersist
    void onCreate() {
        if (createdAt == null) createdAt = LocalDateTime.now();
    }
}
