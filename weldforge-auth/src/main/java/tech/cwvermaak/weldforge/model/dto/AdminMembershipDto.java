package tech.cwvermaak.weldforge.model.dto;

import lombok.*;
import tech.cwvermaak.weldforge.model.AdminRole;

import java.time.LocalDateTime;

/**
 * An admin membership — a grant of admin authority to a user over a tenant
 * (or, when {@link #tenantId} is null, over every tenant). Used as both the
 * request body for a grant and the response shape.
 */
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class AdminMembershipDto {
    private Long id;
    private Long userId;
    /** {@code null} == a global membership: the role applies to every tenant. */
    private Long tenantId;
    private String tenantSlug;
    private AdminRole adminRole;
    /** User id of the admin who granted this membership; null for migration-seeded rows. */
    private Long grantedBy;
    private LocalDateTime grantedAt;
}
