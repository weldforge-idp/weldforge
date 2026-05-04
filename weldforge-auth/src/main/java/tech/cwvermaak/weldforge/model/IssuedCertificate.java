package tech.cwvermaak.weldforge.model;

import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;

/**
 * An end-entity certificate issued by a {@link TenantCertificateAuthority}
 * (PRD X50-01..X50-03). Revocation is append-only: the row stays around
 * with {@code status=REVOKED} until natural expiry so CRL regeneration
 * and OCSP lookups keep returning the correct status.
 */
@Entity
@Table(name = "issued_certificates")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class IssuedCertificate {

    public enum Status { ACTIVE, REVOKED, SUSPENDED, EXPIRED }

    /** Maps directly to {@link java.security.cert.CRLReason} ordinals where they match. */
    public enum RevocationReason {
        UNSPECIFIED,
        KEY_COMPROMISE,
        CA_COMPROMISE,
        AFFILIATION_CHANGED,
        SUPERSEDED,
        CESSATION_OF_OPERATION,
        CERTIFICATE_HOLD,
        PRIVILEGE_WITHDRAWN
    }

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "tenant_id", nullable = false)
    private Tenant tenant;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "ca_id", nullable = false)
    private TenantCertificateAuthority ca;

    @Column(name = "serial_number", nullable = false, unique = true, length = 64)
    private String serialNumber;

    @Column(name = "subject_dn", nullable = false, length = 1024)
    private String subjectDn;

    /** Comma-separated Subject Alternative Names. */
    @Column(columnDefinition = "TEXT")
    private String sans;

    @Column(name = "certificate_pem", nullable = false, columnDefinition = "TEXT")
    private String certificatePem;

    @Column(name = "fingerprint_sha256", nullable = false, length = 128)
    private String fingerprintSha256;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 32)
    @Builder.Default
    private Status status = Status.ACTIVE;

    @Enumerated(EnumType.STRING)
    @Column(name = "revocation_reason", length = 64)
    private RevocationReason revocationReason;

    @Column(name = "revoked_at")
    private LocalDateTime revokedAt;

    @Column(name = "issued_at", nullable = false, updatable = false)
    private LocalDateTime issuedAt;

    @Column(name = "expires_at", nullable = false)
    private LocalDateTime expiresAt;

    /** Optional binding back to the user this cert was issued for. */
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id")
    private User user;

    @PrePersist
    void onCreate() {
        if (issuedAt == null) issuedAt = LocalDateTime.now();
    }
}
