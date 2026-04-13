package tech.cwvermaak.intellisso.model.dto;

import lombok.*;
import tech.cwvermaak.intellisso.model.MfaFactorType;

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
}
