package tech.cwvermaak.weldforge.model;

import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;

/**
 * Audit-trail row capturing a tenant-slug release. Inserted by
 * {@code TenantService.deleteTenant}. Consulted by
 * {@code TenantService.requireSlug} during tenant creation: a slug
 * within its holdback window is refused for reuse, closing the
 * identity-confusion gap where a stolen pre-deletion session could
 * silently identify against a freshly-recreated tenant on the same
 * {@code {slug}.{base-domain}} subdomain.
 *
 * <p>The same slug may appear in multiple rows over its lifetime —
 * each delete writes a fresh release record. The
 * {@code idx_tenant_slug_holdback_slug} index makes "most recent
 * release for slug X" a constant-time lookup.</p>
 *
 * <p>See {@code docs/auth-url-spec.md} §"Slug-reuse holdback".</p>
 */
@Entity
@Table(name = "tenant_slug_holdback")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class TenantSlugHoldback {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, length = 64)
    private String slug;

    @Column(name = "released_at", nullable = false)
    private LocalDateTime releasedAt;

    @Column(name = "released_reason", nullable = false, length = 64)
    private String releasedReason;

    /** Actor that released the slug, when known. Nullable. */
    @Column(name = "released_by_user_id")
    private Long releasedByUserId;
}
