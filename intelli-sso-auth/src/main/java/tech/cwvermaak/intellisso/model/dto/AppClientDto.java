package tech.cwvermaak.intellisso.model.dto;

import lombok.*;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class AppClientDto {
    private Long id;
    private String clientName;
    /** Returned only on create/rotate so the caller can capture it once. */
    private String apiKey;
    private Boolean enabled;
}
