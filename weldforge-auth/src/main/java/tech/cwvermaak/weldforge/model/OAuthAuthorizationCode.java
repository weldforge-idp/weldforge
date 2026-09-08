package tech.cwvermaak.weldforge.model;

import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;

/**
 * Short-lived authorization code issued from {@code /oauth2/authorize} and
 * exchanged at {@code /oauth2/token}. Stored as a SHA-256 hash so a database
 * dump cannot be replayed against the token endpoint.
 *
 * Reuse detection: once {@link #usedAt} is set, any further presentation
 * is rejected with {@code invalid_grant}. We do not auto-revoke the
 * tokens issued from the original exchange (they're already in the
 * client's hands) — but the same code cannot mint two access tokens.
 */
@Entity
@Table(name = "oauth_authorization_codes")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class OAuthAuthorizationCode {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "code_hash", nullable = false, unique = true, length = 128)
    private String codeHash;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "client_id", nullable = false)
    private OidcClient client;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "tenant_id", nullable = false)
    private Tenant tenant;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @Column(name = "redirect_uri", nullable = false, length = 2048)
    private String redirectUri;

    @Column(nullable = false, columnDefinition = "TEXT")
    private String scopes;

    private String nonce;

    @Column(name = "code_challenge")
    private String codeChallenge;

    @Column(name = "code_challenge_method", length = 16)
    private String codeChallengeMethod;

    /**
     * Space-separated RFC 8176 authentication methods from the login that
     * authorised this code, copied onto the tokens at exchange. Null for
     * codes issued before the column existed.
     */
    @Column(name = "amr", length = 255)
    private String amr;

    @Column(name = "expires_at", nullable = false)
    private LocalDateTime expiresAt;

    /**
     * The refresh-token family minted when this code was exchanged (CONF-1.2).
     *
     * <p>Recorded so that a <em>replay</em> can revoke it. Rejecting a replayed
     * code is the visible half of RFC 6749 §4.1.2; the other half is that a
     * replay proves the code leaked, so the tokens the first exchange produced
     * are suspect too. Without this link the code row cannot say what it
     * produced, and the victim of a race they won keeps a live session with no
     * signal that anything happened.
     *
     * <p>Null is legitimate: the client may hold no {@code refresh_token}
     * grant, the code may never have been exchanged, or the row may predate the
     * column.
     */
    @Column(name = "issued_family_id")
    private java.util.UUID issuedFamilyId;

    @Column(name = "used_at")
    private LocalDateTime usedAt;

    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @PrePersist
    void onCreate() {
        if (createdAt == null) createdAt = LocalDateTime.now();
    }
}
