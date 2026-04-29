package tech.cwvermaak.intellisso.model.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CertificateAuthorityDto {
    private Long id;
    private String subjectDn;
    /** PEM-encoded CA certificate — safe to publish. */
    private String certificatePem;
    private String keyAlgorithm;
    private Integer keySize;
    private String signatureAlgorithm;
    private LocalDateTime createdAt;
    private LocalDateTime expiresAt;
}
