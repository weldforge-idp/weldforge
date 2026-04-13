package tech.cwvermaak.intellisso.model.dto;

import lombok.*;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class EnvironmentDto {
    private Long id;
    private String name;
    private String projectName;
    private String description;
}
