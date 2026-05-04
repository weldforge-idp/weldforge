package tech.cwvermaak.weldforge.model.dto;

import lombok.*;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class JwtResponseDto {
    private String token;
    private String type = "Bearer";
    private long expiresIn;
}