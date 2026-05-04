package tech.cwvermaak.weldforge.model;

import jakarta.persistence.*;
import lombok.*;
import tech.cwvermaak.weldforge.config.crypto.EncryptedStringConverter;

import java.time.LocalDateTime;

/**
 * Per-tenant root Certificate Authority (PRD X50-01). The private key
 * is stored encrypted at rest via the shared AES-GCM converter — the
 * same protection every other sensitive secret column uses.
 */
@Entity
@Table(name = "tenant_certificate_authorities")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class TenantCertificateAuthority {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @OneToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "tenant_id", nullable = false, unique = true)
    private Tenant tenant;

    @Column(name = "subject_dn", nullable = false, length = 1024)
    private String subjectDn;

    @Column(name = "certificate_pem", nullable = false, columnDefinition = "TEXT")
    private String certificatePem;

    @Convert(converter = EncryptedStringConverter.class)
    @Column(name = "private_key_enc", nullable = false, columnDefinition = "TEXT")
    private String privateKeyPem;

    @Column(name = "key_algorithm", nullable = false, length = 32)
    @Builder.Default
    private String keyAlgorithm = "RSA";

    @Column(name = "key_size", nullable = false)
    @Builder.Default
    private int keySize = 4096;

    @Column(name = "signature_alg", nullable = false, length = 64)
    @Builder.Default
    private String signatureAlgorithm = "SHA256withRSA";

    /**
     * Monotonic CRL number. Every new CRL bumps this so relying parties
     * can tell the lists apart (RFC 5280 §5.2.3 requires this be strictly
     * increasing).
     */
    @Column(name = "crl_number", nullable = false)
    @Builder.Default
    private long crlNumber = 1;

    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @Column(name = "expires_at", nullable = false)
    private LocalDateTime expiresAt;

    @PrePersist
    void onCreate() {
        if (createdAt == null) createdAt = LocalDateTime.now();
    }
}
