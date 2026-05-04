package tech.cwvermaak.weldforge.model.dto;

import lombok.*;
import tech.cwvermaak.weldforge.model.MfaFactorType;

import java.time.LocalDateTime;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class MfaFactorDto {
    private Long id;
    private MfaFactorType type;
    private String label;
    private Boolean enabled;
    private Boolean verified;
    private LocalDateTime createdAt;
    private LocalDateTime lastUsedAt;

    /** Masked phone for SMS factors, null otherwise. */
    private String phoneMasked;
}
