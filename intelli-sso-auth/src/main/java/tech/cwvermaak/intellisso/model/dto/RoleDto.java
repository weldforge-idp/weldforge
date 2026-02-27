package tech.cwvermaak.intellisso.model.dto;

import lombok.*;

import java.util.List;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class RoleDto {
    private Long id;
    private String name;
    private String description;
    private List<String> responsibilities;   // names only for simplicity
}