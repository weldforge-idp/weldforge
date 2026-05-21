package tech.cwvermaak.weldforge.model;

import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;

/**
 * One-time token sent to a tenant's {@code contact_email} as part of
 * the email-based identity-proofing challenge. On click-through the
 * tenant's {@code verified_at} is flipped to now. The raw token only
 * exists in the email body; this row stores its SHA-256 hash.
 *
 * <p>Mirrors the {@code EmailVerificationToken} / {@code
 * PasswordResetToken} pattern: hashed token, expiry, single-use marker.
 * See {@code docs/auth-url-spec.md} §"Tenant identity-proofing".</p>
 */
@Entity
@Table(name = "tenant_verification_tokens")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class TenantVerificationToken {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "tenant_id", nullable = false)
    private Tenant tenant;

    @Column(name = "token_hash", nullable = false, unique = true, length = 64)
    private String tokenHash;

    /** Snapshot of contact_email at the time the challenge was minted. */
    @Column(name = "contact_email", nullable = false, length = 255)
    private String contactEmail;

    @Column(name = "expires_at", nullable = false)
    private LocalDateTime expiresAt;

    @Column(name = "used_at")
    private LocalDateTime usedAt;

    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @Column(name = "created_by_user_id")
    private Long createdByUserId;

    @PrePersist
    void onCreate() {
        if (createdAt == null) createdAt = LocalDateTime.now();
    }
}
