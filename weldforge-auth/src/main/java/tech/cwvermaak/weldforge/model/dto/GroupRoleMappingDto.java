package tech.cwvermaak.weldforge.model.dto;

import lombok.*;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class GroupRoleMappingDto {

    private Long id;
    private Long scimGroupId;
    private String scimGroupName;
    private Long roleId;
    private String roleName;
    private Integer priority;
}
