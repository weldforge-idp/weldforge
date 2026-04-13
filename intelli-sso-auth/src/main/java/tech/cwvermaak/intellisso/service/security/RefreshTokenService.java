package tech.cwvermaak.intellisso.service.security;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import tech.cwvermaak.intellisso.model.AuditEvent;
import tech.cwvermaak.intellisso.model.RefreshToken;
import tech.cwvermaak.intellisso.model.User;
import tech.cwvermaak.intellisso.repository.RefreshTokenRepository;
import tech.cwvermaak.intellisso.service.audit.AuditService;

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
    public static final String AUDIT_REFRESH_ROTATE = "auth.refresh.rotate";

    private static final SecureRandom RNG = new SecureRandom();

    private final RefreshTokenRepository repository;
    private final RefreshTokenProperties properties;
    private final AuditService auditService;

    /** Mint a brand new token family for a just-completed login. */
    @Transactional
    public Issued issueNew(User user, String ipAddress, String userAgent) {
        return persist(user, UUID.randomUUID(), ipAddress, userAgent);
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
            int revoked = repository.revokeFamily(row.getFamilyId(), now, "reuse_detected");
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

        Issued successor = persist(row.getUser(), row.getFamilyId(), ipAddress, userAgent);
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

    private Issued persist(User user, UUID familyId, String ipAddress, String userAgent) {
        String raw = randomToken();
        RefreshToken row = RefreshToken.builder()
                .user(user)
                .tenant(user.getTenant())
                .familyId(familyId)
                .tokenHash(hash(raw))
                .issuedAt(LocalDateTime.now())
                .expiresAt(LocalDateTime.now().plusDays(properties.getLifetimeDays()))
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
