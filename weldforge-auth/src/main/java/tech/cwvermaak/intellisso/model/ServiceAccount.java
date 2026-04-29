package tech.cwvermaak.intellisso.model;

import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;

/**
 * Machine identity used for non-OAuth2 M2M authentication (PRD TOK-03).
 * Distinct from {@link AppClient} because service accounts carry an
 * explicit {@link AdminRole} — they can act with console-admin privileges
 * without reusing a human user's credentials.
 */
@Entity
@Table(name = "service_accounts")
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class ServiceAccount {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    // EAGER — same reason as AppClient.tenant: accessed from
    // AppAuthorizationFilter outside a transactional scope.
    @ManyToOne(fetch = FetchType.EAGER, optional = false)
    @JoinColumn(name = "tenant_id", nullable = false)
    private Tenant tenant;

    @Column(nullable = false)
    private String name;

    private String description;

    /** Display-safe first 12 chars of the raw token (e.g. {@code wf_svc_abc1}). */
    @Column(name = "token_prefix", nullable = false, length = 32)
    private String tokenPrefix;

    /** SHA-256(raw token), hex-encoded. */
    @Column(name = "token_hash", nullable = false, length = 128)
    private String tokenHash;

    @Enumerated(EnumType.STRING)
    @Column(name = "admin_role", nullable = false, length = 32)
    @Builder.Default
    private AdminRole adminRole = AdminRole.NONE;

    @Column(nullable = false)
    @Builder.Default
    private boolean enabled = true;

    @Column(name = "expires_at")
    private LocalDateTime expiresAt;

    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @Column(name = "last_used_at")
    private LocalDateTime lastUsedAt;

    @PrePersist
    void onCreate() {
        if (createdAt == null) createdAt = LocalDateTime.now();
    }
}
