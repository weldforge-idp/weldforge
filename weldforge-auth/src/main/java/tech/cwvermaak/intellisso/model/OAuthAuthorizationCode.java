package tech.cwvermaak.intellisso.model;

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

    @Column(name = "expires_at", nullable = false)
    private LocalDateTime expiresAt;

    @Column(name = "used_at")
    private LocalDateTime usedAt;

    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @PrePersist
    void onCreate() {
        if (createdAt == null) createdAt = LocalDateTime.now();
    }
}
