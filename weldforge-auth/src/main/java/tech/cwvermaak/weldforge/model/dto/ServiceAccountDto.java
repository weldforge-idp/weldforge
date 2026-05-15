package tech.cwvermaak.weldforge.model.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import tech.cwvermaak.weldforge.model.AdminRole;

import java.time.LocalDateTime;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ServiceAccountDto {
    private Long id;
    private String name;
    private String description;
    /** Slug of the tenant this service account is scoped to. */
    private String tenantSlug;
    /** Human-readable name of the scoping tenant (display name, else name). */
    private String tenantName;
    /** Returned only on create/rotate. */
    private String token;
    private String tokenPrefix;
    private AdminRole adminRole;
    private Boolean enabled;
    private LocalDateTime expiresAt;
    private LocalDateTime createdAt;
    private LocalDateTime lastUsedAt;
}
