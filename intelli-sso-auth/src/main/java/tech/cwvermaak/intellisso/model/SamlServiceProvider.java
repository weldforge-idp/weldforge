package tech.cwvermaak.intellisso.model;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.time.LocalDateTime;
import java.util.Map;

/**
 * A downstream SAML Service Provider that this system (acting as an IdP)
 * can issue signed SAML assertions to. Tenant-scoped via the FK; uniqueness
 * on {@code (tenant_id, entity_id)} is enforced by a partial index in V14.
 */
@Entity
@Table(name = "saml_service_providers",
       uniqueConstraints = @UniqueConstraint(columnNames = {"tenant_id", "entity_id"}))
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class SamlServiceProvider {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "tenant_id", nullable = false)
    private Tenant tenant;

    @Column(name = "entity_id", nullable = false, length = 1024)
    private String entityId;

    @Column(length = 255)
    private String name;

    @Column(name = "acs_url", nullable = false, length = 1024)
    private String acsUrl;

    @Column(name = "slo_url", length = 1024)
    private String sloUrl;

    /** PEM-encoded X.509 certificate for SP request signature verification. */
    @Column(name = "sp_certificate", columnDefinition = "TEXT")
    private String spCertificate;

    @Column(name = "name_id_format", nullable = false, length = 128)
    @Builder.Default
    private String nameIdFormat = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress";

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "attribute_mappings", columnDefinition = "jsonb")
    private Map<String, Object> attributeMappings;

    @Column(nullable = false)
    @Builder.Default
    private Boolean enabled = true;

    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @Column(name = "updated_at", nullable = false)
    private LocalDateTime updatedAt;

    @PrePersist
    void onCreate() {
        LocalDateTime now = LocalDateTime.now();
        if (createdAt == null) createdAt = now;
        updatedAt = now;
    }

    @PreUpdate
    void onUpdate() {
        updatedAt = LocalDateTime.now();
    }
}
