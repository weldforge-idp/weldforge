package tech.cwvermaak.weldforge.model;

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
    /**
     * Optional. Lets this account assign tenant roles whose names start with
     * this prefix, case-insensitively, and nothing else anywhere.
     *
     * <p>A capability in its own right, not a rung on the {@code adminRole}
     * ladder: an account carrying one is expected to have {@code NONE} and
     * reaches exactly two endpoints. It exists so a downstream application can
     * manage its own namespace of roles without being handed
     * {@code TENANT_ADMIN}, which can also delete users, reset MFA and edit
     * OIDC clients across the whole tenant.
     *
     * <p>Null or blank -- which is every account created before V68 -- means
     * no role-grant capability at all.
     *
     * <p>See {@code docs/product/scoped-role-grants.md}.
     */
    @Column(name = "role_grant_prefix", length = 64)
    private String roleGrantPrefix;

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
