package tech.cwvermaak.weldforge.service.security;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import tech.cwvermaak.weldforge.model.AuditEvent;
import tech.cwvermaak.weldforge.model.OidcClient;
import tech.cwvermaak.weldforge.model.RefreshToken;
import tech.cwvermaak.weldforge.model.User;
import tech.cwvermaak.weldforge.repository.RefreshTokenRepository;
import tech.cwvermaak.weldforge.service.audit.AuditService;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.Optional;
import java.util.UUID;

/**
 * Issues and rotates refresh tokens with reuse detection.
 *
 * Every successful login mints a new token in a fresh {@code familyId}.
 * Using a refresh token atomically marks it used and issues a successor in
 * the same family. If the caller presents a token that is already marked
 * used, that's an unambiguous theft signal: the service revokes every
 * token in the family and emits a high-severity audit event. The rightful
 * owner is then forced to re-authenticate, which is the correct outcome —
 * they've lost nothing (they can still log in) and the attacker's stolen
 * cookie is now worthless.
 *
 * The raw token string that goes into the client cookie is never written
 * to the database — only a SHA-256 hash is persisted. A database dump
 * alone cannot be used to forge a valid refresh token.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class RefreshTokenService {

    public static final String AUDIT_REFRESH_REUSE = "auth.refresh.reuse_detected";
    public static final String AUDIT_REFRESH_CLIENT_MISMATCH = "auth.refresh.client_mismatch";
    public static final String AUDIT_REFRESH_ROTATE = "auth.refresh.rotate";

    private static final SecureRandom RNG = new SecureRandom();

    private final RefreshTokenRepository repository;
    private final RefreshTokenFamilyRevoker familyRevoker;
    private final RefreshTokenProperties properties;
    private final AuditService auditService;

    /** Mint a brand new token family for a just-completed login. */
    @Transactional
    public Issued issueNew(User user, String ipAddress, String userAgent) {
        return persist(user, UUID.randomUUID(), null, ipAddress, userAgent);
    }

    /**
     * Mint a token family for an OIDC code exchange, bound to the client that
     * performed it. Only that client may later spend the token.
     */
    @Transactional
    public Issued issueNewForClient(User user, OidcClient client,
                                    String ipAddress, String userAgent) {
        return persist(user, UUID.randomUUID(), client, ipAddress, userAgent);
    }

    /**
     * Rotate an OIDC refresh token on behalf of {@code client}.
     *
     * Adds the client check RFC 6749 §6 requires on top of the reuse detection
     * in {@link #rotate}: a token issued to one relying party must not be
     * spendable by another, or a client that legitimately holds a token for
     * its own users could mint access tokens in a different client's name.
     *
     * A mismatch is treated exactly like reuse — the family dies. A caller
     * presenting someone else's refresh token is either an attacker or a
     * badly-broken client, and in both cases the token should stop working.
     */
    @Transactional
    public Issued rotateForClient(String rawToken, OidcClient client,
                                  String ipAddress, String userAgent) {
        if (client == null) {
            throw new BadCredentialsException("Missing client");
        }
        String hash = hash(rawToken == null ? "" : rawToken);
        RefreshToken row = repository.findByTokenHash(hash)
                .orElseThrow(() -> new BadCredentialsException("Unknown refresh token"));

        Long boundTo = row.getClient() == null ? null : row.getClient().getId();
        if (boundTo == null || !boundTo.equals(client.getId())) {
            // Committed independently — the throw below would otherwise roll it back.
            int revoked = familyRevoker.revoke(row.getFamilyId(), "client_mismatch");
            log.warn("Refresh token presented by the wrong client: user_id={} family_id={} "
                            + "issued_to={} presented_by={} revoked={}",
                    row.getUser().getId(), row.getFamilyId(), boundTo, client.getId(), revoked);
            auditService.log(AuditEvent.builder()
                    .eventType(AUDIT_REFRESH_CLIENT_MISMATCH)
                    .outcome(AuditEvent.Outcome.DENIED)
                    .tenant(row.getUser().getTenant())
                    .actorUser(row.getUser())
                    .actorEmail(row.getUser().getEmail())
                    .targetType("refresh_token_family")
                    .targetId(row.getFamilyId().toString())
                    .metadata(AuditService.meta(
                            "issued_to_client_id", String.valueOf(boundTo),
                            "presented_by_client_id", String.valueOf(client.getId()),
                            "revoked_count", revoked)));
            throw new BadCredentialsException("Refresh token was not issued to this client");
        }
        return rotate(rawToken, ipAddress, userAgent);
    }

    /**
     * Rotate an existing refresh token. Returns the newly-issued successor
     * on success; throws {@link BadCredentialsException} otherwise.
     *
     * This is the reuse-detection choke point: if the presented token is
     * already used or already revoked, the entire family is killed.
     */
    @Transactional
    public Issued rotate(String rawToken, String ipAddress, String userAgent) {
        if (rawToken == null || rawToken.isBlank()) {
            throw new BadCredentialsException("Missing refresh token");
        }
        String hash = hash(rawToken);
        RefreshToken row = repository.findByTokenHash(hash)
                .orElseThrow(() -> new BadCredentialsException("Unknown refresh token"));

        LocalDateTime now = LocalDateTime.now();

        // Reuse detection — a token that's already been used or explicitly
        // revoked is a strong signal of compromise. Nuke the family.
        if (row.getUsedAt() != null || row.getRevokedAt() != null) {
            // Committed independently: this method throws to reject the
            // refresh, and that rollback would otherwise undo the revocation,
            // leaving the stolen family alive with an audit event claiming
            // otherwise.
            int revoked = familyRevoker.revoke(row.getFamilyId(), "reuse_detected");
            log.warn("Refresh token reuse detected: user_id={} family_id={} revoked={}",
                    row.getUser().getId(), row.getFamilyId(), revoked);
            auditService.log(AuditEvent.builder()
                    .eventType(AUDIT_REFRESH_REUSE)
                    .outcome(AuditEvent.Outcome.DENIED)
                    .tenant(row.getUser().getTenant())
                    .actorUser(row.getUser())
                    .actorEmail(row.getUser().getEmail())
                    .targetType("refresh_token_family")
                    .targetId(row.getFamilyId().toString())
                    .metadata(AuditService.meta(
                            "revoked_count", revoked,
                            "original_issued_at", String.valueOf(row.getIssuedAt()))));
            throw new BadCredentialsException("Refresh token reuse detected");
        }

        if (now.isAfter(row.getExpiresAt())) {
            throw new BadCredentialsException("Refresh token expired");
        }

        // Mark current token used, then mint the successor in the same family.
        row.setUsedAt(now);

        Issued successor = persist(row.getUser(), row.getFamilyId(), row.getClient(),
                ipAddress, userAgent);
        row.setReplacedBy(successor.row.getId());

        auditService.recordUserAction(AUDIT_REFRESH_ROTATE, row.getUser(),
                "refresh_token", String.valueOf(row.getId()),
                AuditService.meta("family_id", row.getFamilyId().toString()));

        return successor;
    }

    /**
     * Revoke every active refresh token for a user (e.g. "log me out of all
     * devices"). Access tokens are handled separately by bumping the user's
     * {@code token_version}.
     */
    @Transactional
    public int revokeAllForUser(User user, String reason) {
        return repository.revokeAllForUser(user.getId(), LocalDateTime.now(), reason);
    }

    // ---- helpers -----------------------------------------------------

    private Issued persist(User user, UUID familyId, OidcClient client,
                           String ipAddress, String userAgent) {
        String raw = randomToken();
        // PRD SSO-03: per-tenant refresh TTL overrides the application default.
        LocalDateTime expiresAt;
        Long tenantRefreshMs = user.getTenant() != null ? user.getTenant().getRefreshTtlMs() : null;
        if (tenantRefreshMs != null && tenantRefreshMs > 0) {
            expiresAt = LocalDateTime.now().plusSeconds(tenantRefreshMs / 1000);
        } else {
            expiresAt = LocalDateTime.now().plusDays(properties.getLifetimeDays());
        }
        RefreshToken row = RefreshToken.builder()
                .user(user)
                .tenant(user.getTenant())
                .client(client)
                .familyId(familyId)
                .tokenHash(hash(raw))
                .issuedAt(LocalDateTime.now())
                .expiresAt(expiresAt)
                .ipAddress(ipAddress)
                .userAgent(userAgent)
                .build();
        repository.save(row);
        return new Issued(raw, row);
    }

    /** Result of issuing / rotating — caller hands {@link #rawToken} back to the client. */
    public record Issued(String rawToken, RefreshToken row) {}

    /** Public so BDD step definitions in another package can simulate DB lookup by hash. */
    public static String hash(String rawToken) {
        try {
            MessageDigest sha = MessageDigest.getInstance("SHA-256");
            byte[] out = sha.digest(rawToken.getBytes(StandardCharsets.UTF_8));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(out);
        } catch (Exception e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }

    private static String randomToken() {
        byte[] buf = new byte[48];
        RNG.nextBytes(buf);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(buf);
    }

    /** Visible for tests so they can exercise the internals without reflection. */
    public Optional<RefreshToken> findByRaw(String rawToken) {
        return repository.findByTokenHash(hash(rawToken));
    }
}
