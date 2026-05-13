package tech.cwvermaak.weldforge.model;

import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;

/**
 * Maps a public hostname to a tenant. A request arriving on this host
 * is internally forwarded to /t/{slug}/... so the existing path-based
 * OIDC / SAML controllers handle it.
 */
@Entity
@Table(name = "tenant_hosts")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class TenantHost {

    @Id
    @Column(length = 253)
    private String host;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "tenant_id", nullable = false)
    private Tenant tenant;

    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @PrePersist
    void onCreate() {
        if (createdAt == null) createdAt = LocalDateTime.now();
    }
}
