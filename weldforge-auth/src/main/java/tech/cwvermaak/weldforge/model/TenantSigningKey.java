package tech.cwvermaak.weldforge.model;

import jakarta.persistence.*;
import lombok.*;
import tech.cwvermaak.weldforge.config.crypto.EncryptedStringConverter;

import java.time.LocalDateTime;

/**
 * RSA signing keypair owned by a tenant. The private key is encrypted at
 * rest via {@link EncryptedStringConverter}; the public key sits in
 * plaintext PEM and is exposed through the JWKS endpoint.
 *
 * Multiple keys may exist per tenant during a rotation window — old keys
 * remain {@code active=false} but readable so previously-issued tokens
 * can still be verified until they expire.
 */
@Entity
@Table(name = "tenant_signing_keys")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class TenantSigningKey {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "tenant_id", nullable = false)
    private Tenant tenant;

    /** Stable JWK key id; published in the JWKS and the JWS header. */
    @Column(nullable = false, unique = true, length = 64)
    private String kid;

    @Column(nullable = false, length = 16)
    @Builder.Default
    private String algorithm = "RS256";

    @Column(name = "public_key_pem", nullable = false, columnDefinition = "TEXT")
    private String publicKeyPem;

    /** AES-GCM encrypted PEM. Never logged, never returned via the API. */
    @Convert(converter = EncryptedStringConverter.class)
    @Column(name = "private_key_enc", nullable = false, columnDefinition = "TEXT")
    private String privateKeyPem;

    @Column(nullable = false)
    @Builder.Default
    private Boolean active = true;

    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @Column(name = "rotated_at")
    private LocalDateTime rotatedAt;

    @PrePersist
    void onCreate() {
        if (createdAt == null) createdAt = LocalDateTime.now();
        if (active == null) active = true;
    }
}
