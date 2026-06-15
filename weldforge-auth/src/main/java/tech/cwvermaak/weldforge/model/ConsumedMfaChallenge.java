package tech.cwvermaak.weldforge.model;

import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;

/**
 * Records an MFA challenge token (by its {@code jti}) that has already been
 * spent on a successful login, so the same challenge token cannot be replayed
 * (B-MFA-2). Rows are pruned once {@link #expiresAt} has passed.
 */
@Entity
@Table(name = "consumed_mfa_challenge")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class ConsumedMfaChallenge {

    /** The challenge token's JWT id (jti). */
    @Id
    @Column(name = "jti", length = 64)
    private String jti;

    /** The token's own expiry — after this the row is safe to prune. */
    @Column(name = "expires_at", nullable = false)
    private LocalDateTime expiresAt;

    @Column(name = "consumed_at", nullable = false)
    private LocalDateTime consumedAt;

    @PrePersist
    void onCreate() {
        if (consumedAt == null) consumedAt = LocalDateTime.now();
    }
}
