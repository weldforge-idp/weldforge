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
    /**
     * When the token stops authenticating. Null means it never does.
     *
     * <p>Computed on write from {@link #expiresInDays} / {@link #expiresInHours}
     * and returned on read. Supplying it directly still works, for callers
     * written before the duration fields existed.
     */
    private LocalDateTime expiresAt;
    /**
     * Requested lifetime in whole days. <strong>0 means the token never
     * expires;</strong> omitting both duration fields leaves an existing
     * expiry untouched.
     */
    private Integer expiresInDays;
    /** Additional hours on top of {@link #expiresInDays}; same 0 rule. */
    private Integer expiresInHours;
    private LocalDateTime createdAt;
    private LocalDateTime lastUsedAt;
}
