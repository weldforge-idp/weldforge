package tech.cwvermaak.weldforge.model;

import jakarta.persistence.*;
import lombok.*;
import tech.cwvermaak.weldforge.config.crypto.EncryptedStringConverter;

import java.time.LocalDateTime;

/**
 * A second-factor credential bound to a {@link User}. The user owns a tenant,
 * so tenant scoping is transitive through {@code user_id}.
 *
 * TOTP rows use {@link #totpSecretEnc} (encrypted at rest via
 * {@link EncryptedStringConverter}). WebAuthn rows use the credential/public
 * key/signature-count fields; {@code user_handle} is the stable per-user
 * identifier handed back to the authenticator.
 */
@Entity
@Table(name = "user_mfa_factors")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class MfaFactor {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 16)
    private MfaFactorType type;

    @Column(length = 128)
    private String label;

    /** Base32 TOTP secret, encrypted at rest. Null for WebAuthn factors. */
    @Convert(converter = EncryptedStringConverter.class)
    @Column(name = "totp_secret_enc", columnDefinition = "TEXT")
    private String totpSecretEnc;

    // -- WebAuthn fields ------------------------------------------------

    /** Base64url-encoded credential id. */
    @Column(name = "credential_id", columnDefinition = "TEXT")
    private String credentialId;

    /** Base64url-encoded COSE public key. */
    @Column(name = "public_key_cose", columnDefinition = "TEXT")
    private String publicKeyCose;

    @Column(name = "signature_count", nullable = false)
    @Builder.Default
    private Long signatureCount = 0L;

    /**
     * WebAuthn only (CONF-3.2): true when this credential was enrolled under a
     * {@code REQUIRED} user-verification policy.
     *
     * <p>A credential used as a second factor should verify the user, or the
     * factor is only "the key is plugged in". Both ceremonies previously asked
     * for {@code PREFERRED}, which an authenticator may ignore, and nothing
     * recorded whether it complied. Demanding UV globally at assertion time
     * would lock out credentials enrolled on authenticators without the
     * capability — so the requirement is recorded here at enrolment, and the
     * assertion ceremony demands UV only when every one of the user's
     * credentials carries it.
     *
     * <p>False for credentials enrolled before this column existed; the
     * population self-heals as users re-enrol.
     */
    @Column(name = "uv_required", nullable = false)
    @Builder.Default
    private boolean uvRequired = false;

    @Column(length = 64)
    private String aaguid;

    /** Stable per-user handle returned by the authenticator. Base64url. */
    @Column(name = "user_handle", columnDefinition = "TEXT")
    private String userHandle;

    // -- SMS OTP fields -------------------------------------------------

    /** E.164 phone number the code is delivered to. Populated only for SMS rows. */
    @Column(name = "phone_number", length = 32)
    private String phoneNumber;

    /** BCrypt hash of the pending OTP code. Cleared on verify. */
    @Column(name = "sms_code_hash", length = 128)
    private String smsCodeHash;

    /** Expiry time for the pending OTP. */
    @Column(name = "sms_code_expires_at")
    private LocalDateTime smsCodeExpiresAt;

    // -- Lifecycle ------------------------------------------------------

    @Column(nullable = false)
    @Builder.Default
    private Boolean enabled = true;

    @Column(nullable = false)
    @Builder.Default
    private Boolean verified = false;

    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @Column(name = "last_used_at")
    private LocalDateTime lastUsedAt;

    /**
     * The last TOTP time-step (epoch-seconds / 30) accepted for this factor.
     * A code whose step is {@code <=} this is rejected as a replay (RFC 6238).
     * Null until the first successful verification. TOTP factors only.
     */
    @Column(name = "last_totp_step")
    private Long lastTotpStep;

    @PrePersist
    void onCreate() {
        if (createdAt == null) createdAt = LocalDateTime.now();
        if (signatureCount == null) signatureCount = 0L;
        if (enabled == null) enabled = true;
        if (verified == null) verified = false;
    }
}
