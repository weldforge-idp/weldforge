package tech.cwvermaak.weldforge.model;

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

    /**
     * When set, every assertion to this SP carries this
     * {@code AuthnContextClassRef} verbatim rather than one derived from the
     * session (CONF-5.1).
     *
     * <p>The escape hatch for an SP configured to accept only the old
     * hardcoded {@code PasswordProtectedTransport}: such an SP would break the
     * day one of its users enables MFA, and that failure looks like an IdP
     * outage rather than a policy mismatch.
     */
    @Column(name = "authn_context_override", length = 255)
    private String authnContextOverride;

    /**
     * When true the assertion {@code Issuer} is the metadata {@code entityID},
     * which is what a conformant SP expects (CONF-5.4).
     *
     * <p>Defaults false, preserving the legacy {@code {slug}-idp} value. This
     * is the most breaking change available here: an SP matches inbound
     * assertions against a configured issuer string, so flipping it before the
     * SP is reconfigured rejects every assertion.
     */
    @Column(name = "use_entity_id_as_issuer", nullable = false)
    @Builder.Default
    private Boolean useEntityIdAsIssuer = false;

    /**
     * B-SAML-1(a). When {@code true}, the IdP requires inbound AuthnRequests
     * (and LogoutRequests) from this SP to carry a valid XML signature
     * verifiable against {@link #spCertificate}, and rejects unsigned or
     * badly-signed requests. Default {@code false} for backward compatibility.
     */
    @Column(name = "want_authn_request_signed", nullable = false)
    @Builder.Default
    private Boolean wantAuthnRequestSigned = false;

    @Column(name = "name_id_format", nullable = false, length = 128)
    @Builder.Default
    private String nameIdFormat = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress";

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "attribute_mappings", columnDefinition = "jsonb")
    private Map<String, Object> attributeMappings;

    @Column(nullable = false)
    @Builder.Default
    private Boolean enabled = true;

    /**
     * PRD SAM-04. When {@code true} and {@link #spCertificate} is set,
     * the IdP wraps the signed assertion in an {@code <EncryptedAssertion>}
     * element encrypted to the SP's public key.
     */
    @Column(name = "encrypt_assertions", nullable = false)
    @Builder.Default
    private Boolean encryptAssertions = false;

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
