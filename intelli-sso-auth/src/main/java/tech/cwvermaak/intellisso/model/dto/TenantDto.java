package tech.cwvermaak.intellisso.model.dto;

import lombok.*;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class TenantDto {
    private Long id;
    private String slug;
    private String name;
    private String displayName;
    private Boolean enabled;
}
