package tech.cwvermaak.intellisso.model.dto;

import lombok.Builder;
import lombok.Data;
import tech.cwvermaak.intellisso.model.AuthProvider;

@Data
@Builder
public class UserResponseDto {
    private Long id;
    private String name;
    private String email;
    private String imageUrl;
    private AuthProvider provider;
    private String role;
}
