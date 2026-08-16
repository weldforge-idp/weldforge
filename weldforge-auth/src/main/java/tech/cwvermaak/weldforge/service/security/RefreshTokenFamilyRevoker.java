package tech.cwvermaak.weldforge.service.security;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import tech.cwvermaak.weldforge.repository.RefreshTokenRepository;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * Revokes a refresh-token family in its own transaction.
 *
 * <p>This exists because of an ordering trap. Reuse detection revokes the
 * family and then throws, so the caller sees a failed refresh — but the throw
 * rolls back the caller's transaction, and the revocation with it. The result
 * was the worst possible outcome: an audit event saying the theft was detected
 * while every token in the family stayed valid, so the attacker kept working
 * and the log said otherwise.
 *
 * <p>{@code REQUIRES_NEW} commits the revocation independently, so it survives
 * the rollback. It must be a separate bean rather than a method on
 * {@code RefreshTokenService}: a self-invocation bypasses the proxy and the
 * propagation setting would be silently ignored.
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class RefreshTokenFamilyRevoker {

    private final RefreshTokenRepository repository;

    /** Revoke every un-revoked token in the family. Returns how many were hit. */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public int revoke(UUID familyId, String reason) {
        int revoked = repository.revokeFamily(familyId, LocalDateTime.now(), reason);
        log.warn("Revoked refresh token family {} ({}): {} token(s)", familyId, reason, revoked);
        return revoked;
    }
}
