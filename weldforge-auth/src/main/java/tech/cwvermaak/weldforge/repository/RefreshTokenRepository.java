package tech.cwvermaak.weldforge.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import tech.cwvermaak.weldforge.model.RefreshToken;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {

    Optional<RefreshToken> findByTokenHash(String tokenHash);

    List<RefreshToken> findByFamilyId(UUID familyId);

    List<RefreshToken> findByUserIdAndRevokedAtIsNull(Long userId);

    /**
     * True once any token in the family has been revoked, i.e. the login
     * session the family represents has been ended (CONF-5.2). Rotation never
     * sets {@code revokedAt} -- only {@link #revokeFamily}, the per-user and
     * per-tenant sweeps do, and each of those revokes the whole family.
     */
    boolean existsByFamilyIdAndRevokedAtIsNotNull(UUID familyId);

    /**
     * Atomically mark every token in a family as revoked. Used on reuse
     * detection and on explicit logout-all.
     */
    @Modifying
    @Query("""
        update RefreshToken r
        set r.revokedAt = :now, r.revokedReason = :reason
        where r.familyId = :familyId and r.revokedAt is null
        """)
    int revokeFamily(@Param("familyId") UUID familyId,
                     @Param("now")      LocalDateTime now,
                     @Param("reason")   String reason);

    @Modifying
    @Query("""
        update RefreshToken r
        set r.revokedAt = :now, r.revokedReason = :reason
        where r.user.id = :userId and r.revokedAt is null
        """)
    int revokeAllForUser(@Param("userId") Long userId,
                         @Param("now")    LocalDateTime now,
                         @Param("reason") String reason);

    /**
     * Revoke every live refresh token belonging to a tenant — paired with
     * {@code UserRepository.bumpTokenVersionForTenant} during tenant
     * deletion so no stolen-but-not-yet-rotated refresh token can survive
     * the tenant going away.
     */
    @Modifying
    @Query("""
        update RefreshToken r
        set r.revokedAt = :now, r.revokedReason = :reason
        where r.tenant.id = :tenantId and r.revokedAt is null
        """)
    int revokeAllForTenant(@Param("tenantId") Long tenantId,
                           @Param("now")      LocalDateTime now,
                           @Param("reason")   String reason);

    /**
     * Claim this refresh token for the current rotation, atomically. Returns 1
     * if this caller won it, 0 if it was already used or revoked.
     *
     * <p>Same reasoning as {@code OAuthAuthorizationCodeRepository.claim}, and
     * the same defect it replaces: testing {@code usedAt}/{@code revokedAt} in
     * Java and writing afterwards lets two concurrent rotations both pass the
     * test under READ COMMITTED, so both mint a successor and reuse detection
     * never fires. That detection is what turns a stolen long-lived credential
     * into a contained incident, so losing it to a race loses the control
     * exactly when it is being exercised. B-AUTH-6, 2026-09-14 review.
     *
     * <p>A zero return is not simply "no": it means somebody else holds this
     * token too. The caller must run the reuse path, not retry.
     *
     * <p><strong>REQUIRES_NEW, and it must stay that way.</strong> A lost claim
     * is followed by the family revoke, which is itself REQUIRES_NEW so the
     * caller's rejection cannot roll the containment back. Both statements
     * target this same table and this same row. Left in the caller's
     * transaction, the failed claim holds a tuple lock that the revoke — on a
     * different connection — then waits for, while the caller waits for the
     * revoke to return. Postgres sees one session waiting on another's lock and
     * no cycle, so it never fires the deadlock detector: the request simply
     * hangs until something times out.
     *
     * <p>Running the claim in its own transaction releases the lock the moment
     * it resolves, so the revoke that follows finds the row free. Found by
     * {@code SingleUseUnderConcurrencyIntegrationTest}, which hung at two
     * racers before this annotation existed.
     *
     * <p>The consequence to accept: this write commits independently, so a
     * token claimed here stays claimed even if the caller throws afterwards.
     * The only check that follows is expiry, and consuming an already-expired
     * token costs nothing.
     *
     * <p>The authorization-code claim deliberately does NOT do this. Its reuse
     * path revokes refresh-token rows, a different table entirely, so no lock
     * conflict exists — and staying in the caller's transaction keeps the code
     * retryable when a later validation check fails.
     */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    @Modifying
    @Query("""
        update RefreshToken r
        set r.usedAt = :now
        where r.id = :id and r.usedAt is null and r.revokedAt is null
        """)
    int claim(@Param("id") Long id, @Param("now") LocalDateTime now);

    /**
     * Record the successor without touching the managed entity.
     *
     * <p>This exists because mutating the entity was actively dangerous. The
     * rotating caller loaded the row, then set usedAt and replacedBy on it,
     * which made it dirty — and JPA flushes the WHOLE row at commit, from a
     * snapshot taken before the load. A concurrent reuse sweep that revoked the
     * family in between was therefore overwritten with the stale
     * {@code revoked_at = null}: the containment ran, audited itself as
     * successful, and was then silently undone by the winner committing.
     *
     * <p>That hazard predates the atomic-claim work; it was simply invisible
     * until {@code SingleUseUnderConcurrencyIntegrationTest} raced the two
     * paths against each other. Targeted column writes, and no dirty entity,
     * is the fix.
     */
    @Modifying
    @Query("update RefreshToken r set r.replacedBy = :successorId where r.id = :id")
    int markReplacedBy(@Param("id") Long id, @Param("successorId") Long successorId);
}
