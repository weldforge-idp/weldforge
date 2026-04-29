package tech.cwvermaak.intellisso.model;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.time.LocalDateTime;
import java.util.Map;

/**
 * Append-only record of a security-relevant event. Never mutated after
 * insert. Tenant id is nullable because a failed login doesn't always know
 * a tenant yet, and some super-admin actions span tenants.
 */
@Entity
@Table(name = "audit_events")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class AuditEvent {

    public enum Outcome { SUCCESS, FAILURE, DENIED }

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "tenant_id")
    private Tenant tenant;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "actor_user_id")
    private User actorUser;

    @Column(name = "actor_email")
    private String actorEmail;

    @Column(name = "actor_is_super_admin", nullable = false)
    @Builder.Default
    private Boolean actorIsSuperAdmin = false;

    @Column(name = "event_type", nullable = false, length = 64)
    private String eventType;

    @Column(name = "target_type", length = 64)
    private String targetType;

    @Column(name = "target_id", length = 255)
    private String targetId;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 16)
    @Builder.Default
    private Outcome outcome = Outcome.SUCCESS;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(columnDefinition = "jsonb")
    private Map<String, Object> metadata;

    @Column(name = "ip_address", length = 45)
    private String ipAddress;

    @Column(name = "user_agent", length = 512)
    private String userAgent;

    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @PrePersist
    void onCreate() {
        if (createdAt == null) createdAt = LocalDateTime.now();
        if (outcome == null) outcome = Outcome.SUCCESS;
        if (actorIsSuperAdmin == null) actorIsSuperAdmin = false;
    }
}
