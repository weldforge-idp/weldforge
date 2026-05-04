package tech.cwvermaak.weldforge.model;

import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.Set;

/**
 * RFC 7643 §4.2 SCIM Group. Deliberately separate from the internal
 * {@link Role} entity: Roles are application RBAC primitives that the
 * admin portal manages, while SCIM Groups are pushed by upstream
 * provisioners (Okta / Workday / Entra ID) to drive downstream
 * permissions.
 *
 * Tenant-scoped via the FK; uniqueness on {@code (tenant_id, lower(name))}
 * is enforced by a partial index in V13.
 */
@Entity
@Table(name = "scim_groups")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class ScimGroup {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "tenant_id", nullable = false)
    private Tenant tenant;

    @Column(nullable = false, length = 255)
    private String name;

    @Column(name = "display_name", length = 255)
    private String displayName;

    @Column(name = "external_id", length = 255)
    private String externalId;

    @ManyToMany(fetch = FetchType.LAZY)
    @JoinTable(
            name = "scim_group_members",
            joinColumns = @JoinColumn(name = "group_id"),
            inverseJoinColumns = @JoinColumn(name = "user_id"))
    @Builder.Default
    private Set<User> members = new HashSet<>();

    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @Column(name = "updated_at", nullable = false)
    private LocalDateTime updatedAt;

    @PrePersist
    void onCreate() {
        LocalDateTime now = LocalDateTime.now();
        if (createdAt == null) createdAt = now;
        updatedAt = now;
        if (members == null) members = new HashSet<>();
    }

    @PreUpdate
    void onUpdate() {
        updatedAt = LocalDateTime.now();
    }
}
