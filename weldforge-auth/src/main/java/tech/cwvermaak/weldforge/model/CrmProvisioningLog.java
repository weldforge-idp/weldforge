package tech.cwvermaak.weldforge.model;

import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;

/**
 * Dedupe + observability ledger for CRM pushes (PRD CRM-04). One row per
 * (provider, user); the {@code externalId} column is populated on first
 * successful push so subsequent logins can upsert instead of creating a
 * duplicate record downstream.
 */
@Entity
@Table(name = "crm_provisioning_log")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class CrmProvisioningLog {

    public enum Status { PENDING, SUCCESS, FAILED, SKIPPED }

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "provider_id", nullable = false)
    private TenantCrmProvider provider;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "tenant_id", nullable = false)
    private Tenant tenant;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    /** The id the downstream CRM returned on first create — used for subsequent upserts. */
    @Column(name = "external_id", length = 255)
    private String externalId;

    /** Concatenated match-key values — used for cross-user dedupe (e.g. shared inbox). */
    @Column(name = "match_key_value", length = 512)
    private String matchKeyValue;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 32)
    @Builder.Default
    private Status status = Status.PENDING;

    @Column(name = "last_error", columnDefinition = "TEXT")
    private String lastError;

    @Column(nullable = false)
    @Builder.Default
    private int attempts = 0;

    @Column(name = "last_event_type", length = 64)
    private String lastEventType;

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
