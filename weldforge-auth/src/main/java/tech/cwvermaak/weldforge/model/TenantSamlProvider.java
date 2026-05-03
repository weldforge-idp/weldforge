package tech.cwvermaak.weldforge.model;

import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;

/**
 * Per-tenant upstream SAML 2.0 Identity Provider configuration. One row per
 * (tenant, providerKey) — resolved at request time by
 * {@code DatabaseRelyingPartyRegistrationRepository}.
 */
@Entity
@Table(name = "tenant_saml_providers",
       uniqueConstraints = @UniqueConstraint(columnNames = {"tenant_id", "provider_key"}))
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class TenantSamlProvider {

    public enum Binding { POST, REDIRECT }

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "tenant_id", nullable = false)
    private Tenant tenant;

    @Column(name = "provider_key", nullable = false, length = 64)
    private String providerKey;

    @Column(name = "display_name", length = 128)
    private String displayName;

    @Column(name = "idp_entity_id", nullable = false, length = 1024)
    private String idpEntityId;

    @Column(name = "idp_sso_url", nullable = false, length = 1024)
    private String idpSsoUrl;

    @Column(name = "idp_slo_url", length = 1024)
    private String idpSloUrl;

    @Enumerated(EnumType.STRING)
    @Column(name = "sso_binding", nullable = false, length = 16)
    @Builder.Default
    private Binding ssoBinding = Binding.POST;

    /** PEM-encoded X.509 certificate (BEGIN/END CERTIFICATE). */
    @Column(name = "idp_signing_certificate", nullable = false, columnDefinition = "TEXT")
    private String idpSigningCertificate;

    @Column(name = "name_id_format", length = 64)
    private String nameIdFormat;

    @Column(name = "email_attribute", nullable = false, length = 128)
    @Builder.Default
    private String emailAttribute = "email";

    @Column(name = "name_attribute", nullable = false, length = 128)
    @Builder.Default
    private String nameAttribute = "name";

    @Column(name = "want_assertions_signed", nullable = false)
    @Builder.Default
    private Boolean wantAssertionsSigned = true;

    @Column(name = "want_authn_req_signed", nullable = false)
    @Builder.Default
    private Boolean wantAuthnRequestSigned = false;

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
