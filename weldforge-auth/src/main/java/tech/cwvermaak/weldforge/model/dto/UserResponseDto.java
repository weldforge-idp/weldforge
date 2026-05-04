package tech.cwvermaak.weldforge.model.dto;

import lombok.Builder;
import lombok.Data;
import tech.cwvermaak.weldforge.model.AdminRole;
import tech.cwvermaak.weldforge.model.AuthProvider;

@Data
@Builder
public class UserResponseDto {
    private Long id;
    private String name;
    private String email;
    private String imageUrl;
    private AuthProvider provider;
    private String role;

    /** PRD ADM-02: admin console role (NONE / READ_ONLY / TENANT_ADMIN / SUPER_ADMIN). */
    private AdminRole adminRole;
}
