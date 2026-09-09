package tech.cwvermaak.weldforge.model;

import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;

/**
 * An in-flight WebAuthn ceremony (CONF-3.1).
 *
 * <p>A ceremony is two requests: the first mints a random challenge the server
 * must remember, the second presents the authenticator's response to be checked
 * against it. That memory used to live in a {@code ConcurrentHashMap} on
 * whichever instance served the first request, which failed across a rolling
 * update and was the only thing preventing a second replica.
 *
 * <p>Rows are single-use — {@code finish} deletes before verifying, so a replay
 * finds nothing — and carry an expiry so an abandoned ceremony (a user closing
 * the tab at the browser prompt, which is common) is pruned rather than leaked.
 */
@Entity
@Table(name = "webauthn_ceremony")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class WebAuthnCeremony {

    /** Which ceremony this is; the two are stored together but never interchangeable. */
    public enum Type { REGISTRATION, ASSERTION }

    /**
     * The challenge token the client already round-trips between the two
     * requests. Reused as the key so no new identifier crosses the wire.
     */
    @Id
    @Column(name = "challenge_token", length = 128)
    private String challengeToken;

    /**
     * The user the ceremony was started for. Checked on completion, so a
     * challenge token cannot be redeemed against a different account.
     */
    @Column(name = "user_id", nullable = false)
    private Long userId;

    @Enumerated(EnumType.STRING)
    @Column(name = "ceremony_type", nullable = false, length = 16)
    private Type ceremonyType;

    /**
     * The Yubico library's own serialised options, held opaque. Re-parsing and
     * rebuilding them could introduce a difference between what was issued and
     * what is verified — which is precisely what a challenge exists to prevent.
     */
    @Column(name = "options_json", nullable = false, columnDefinition = "TEXT")
    private String optionsJson;

    @Column(name = "created_at", nullable = false)
    private LocalDateTime createdAt;

    @Column(name = "expires_at", nullable = false)
    private LocalDateTime expiresAt;

    @PrePersist
    void onCreate() {
        if (createdAt == null) createdAt = LocalDateTime.now();
    }
}
