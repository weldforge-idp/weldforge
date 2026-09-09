package tech.cwvermaak.weldforge.model;

import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;

/**
 * An AuthnRequest ID already processed (CONF-5.3).
 *
 * <p>Without this a captured AuthnRequest could be replayed to mint a second
 * assertion. The existing mitigations were real but incidental — an
 * authenticated browser session is still required, and ACS and Audience come
 * from stored SP configuration rather than the request — and none of them is
 * the control.
 *
 * <p>Rows expire rather than accumulating: a request older than its freshness
 * window is refused on that ground anyway, so the row stops carrying
 * information. Same shape as {@link ConsumedMfaChallenge}.
 */
@Entity
@Table(name = "saml_request_replay")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class SamlRequestReplay {

    /** The AuthnRequest's own ID attribute. */
    @Id
    @Column(name = "request_id", length = 255)
    private String requestId;

    @Column(name = "tenant_id", nullable = false)
    private Long tenantId;

    /** Recorded for the audit trail; a replay is worth attributing to an SP. */
    @Column(name = "sp_entity_id", length = 512)
    private String spEntityId;

    @Column(name = "seen_at", nullable = false)
    private LocalDateTime seenAt;

    @Column(name = "expires_at", nullable = false)
    private LocalDateTime expiresAt;

    @PrePersist
    void onCreate() {
        if (seenAt == null) seenAt = LocalDateTime.now();
    }
}
