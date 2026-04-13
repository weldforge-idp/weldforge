package tech.cwvermaak.intellisso.model;

import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;

/**
 * Single row in the OIDC token revocation list. Holds only a SHA-256 hash
 * of the original token so a database leak cannot be replayed.
 */
@Entity
@Table(name = "revoked_oidc_tokens")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class RevokedOidcToken {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "token_hash", nullable = false, unique = true, length = 128)
    private String tokenHash;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "tenant_id", nullable = false)
    private Tenant tenant;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "client_id")
    private OidcClient client;

    @Column(name = "expires_at", nullable = false)
    private LocalDateTime expiresAt;

    @Column(name = "revoked_at", nullable = false)
    private LocalDateTime revokedAt;

    @Column(name = "revoked_reason", length = 64)
    private String revokedReason;

    @PrePersist
    void onCreate() {
        if (revokedAt == null) revokedAt = LocalDateTime.now();
    }
}
