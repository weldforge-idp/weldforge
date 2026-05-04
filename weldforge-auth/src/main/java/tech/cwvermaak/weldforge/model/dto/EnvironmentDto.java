package tech.cwvermaak.weldforge.model.dto;

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
