package tech.cwvermaak.weldforge.model;

import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;

/**
 * A grant of admin authority to a user over a tenant — the many-to-many
 * "admin reach" model from cross-tenant-admin-spec.md.
 *
 * <p>{@link #tenant} {@code == null} is a <b>global</b> membership: the role
 * applies to every tenant, present and future. A concrete tenant is a
 * per-tenant membership. {@code SUPER_ADMIN} is only meaningful on a global
 * row; a per-tenant {@code SUPER_ADMIN} grant is treated as {@code TENANT_ADMIN}.
 *
 * <p>This table holds <i>human user</i> memberships. Service-account reach is
 * not row-modelled: a {@code SUPER_ADMIN} service-account token is itself the
 * platform-operator credential and is treated as global; lesser service
 * accounts stay scoped to their home tenant.
 */
@Entity
@Table(name = "admin_membership")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class AdminMembership {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    /** {@code null} == GLOBAL scope: the role applies to every tenant. */
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "tenant_id")
    private Tenant tenant;

    @Enumerated(EnumType.STRING)
    @Column(name = "admin_role", nullable = false, length = 32)
    private AdminRole adminRole;

    /** User id of the admin who granted this membership; null for migration-seeded rows. */
    @Column(name = "granted_by")
    private Long grantedBy;

    @Column(name = "granted_at", nullable = false)
    private LocalDateTime grantedAt;

    @PrePersist
    void onCreate() {
        if (grantedAt == null) grantedAt = LocalDateTime.now();
    }

    /** True for a global membership — the role applies to every tenant. */
    public boolean isGlobal() {
        return tenant == null;
    }
}
