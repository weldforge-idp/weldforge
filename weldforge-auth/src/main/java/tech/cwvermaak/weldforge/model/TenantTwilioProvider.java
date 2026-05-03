package tech.cwvermaak.weldforge.model;

import jakarta.persistence.*;
import lombok.*;
import tech.cwvermaak.weldforge.config.crypto.EncryptedStringConverter;

import java.time.LocalDateTime;

/**
 * Per-tenant Twilio configuration. Each tenant can use its own Twilio
 * subaccount with its own Account SID, auth token, and caller-id phone
 * number. The auth token is AES-GCM encrypted at rest via
 * {@link EncryptedStringConverter}.
 *
 * One row per tenant — unique index on {@code tenant_id}. A tenant that
 * needs multiple SMS senders can use a Twilio Messaging Service and
 * reference its SID here instead.
 */
@Entity
@Table(name = "tenant_twilio_providers",
       uniqueConstraints = @UniqueConstraint(columnNames = "tenant_id"))
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class TenantTwilioProvider {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @OneToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "tenant_id", nullable = false, unique = true)
    private Tenant tenant;

    /** Twilio Account SID — AC... (public identifier, not sensitive). */
    @Column(name = "account_sid", nullable = false, length = 128)
    private String accountSid;

    /** Twilio Auth Token — AES-GCM encrypted at rest. Never logged or returned over API. */
    @Convert(converter = EncryptedStringConverter.class)
    @Column(name = "auth_token_enc", nullable = false, columnDefinition = "TEXT")
    private String authToken;

    /** E.164 phone number the tenant's SMS originates from. */
    @Column(name = "from_phone", nullable = false, length = 32)
    private String fromPhone;

    /** Optional Messaging Service SID for sender pool routing. */
    @Column(name = "messaging_service_sid", length = 128)
    private String messagingServiceSid;

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
        if (enabled == null) enabled = true;
    }

    @PreUpdate
    void onUpdate() {
        updatedAt = LocalDateTime.now();
    }
}
