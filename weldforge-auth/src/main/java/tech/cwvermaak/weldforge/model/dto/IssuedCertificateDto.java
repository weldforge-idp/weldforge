package tech.cwvermaak.weldforge.model.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import tech.cwvermaak.weldforge.model.IssuedCertificate;

import java.time.LocalDateTime;
import java.util.List;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class IssuedCertificateDto {
    private Long id;
    private String serialNumber;
    private String subjectDn;
    private List<String> sans;
    /**
     * Returned only on issuance so the caller can capture the PEM once.
     * Subsequent reads do not echo the private key — end-entity keys
     * never leave the caller in the first place.
     */
    private String certificatePem;
    /** Returned only on issuance. Never persisted. */
    private String privateKeyPem;
    private String fingerprintSha256;
    private IssuedCertificate.Status status;
    private IssuedCertificate.RevocationReason revocationReason;
    private LocalDateTime revokedAt;
    private LocalDateTime issuedAt;
    private LocalDateTime expiresAt;
    /** Validity requested at issuance time (days). Input-only. */
    private Integer validityDays;
    /** User id to bind the cert to (X50-03 client cert → user lookup). */
    private Long userId;
}
