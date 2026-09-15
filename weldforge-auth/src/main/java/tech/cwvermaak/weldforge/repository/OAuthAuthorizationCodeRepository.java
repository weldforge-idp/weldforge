package tech.cwvermaak.weldforge.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import tech.cwvermaak.weldforge.model.OAuthAuthorizationCode;

import java.time.LocalDateTime;
import java.util.Optional;

public interface OAuthAuthorizationCodeRepository extends JpaRepository<OAuthAuthorizationCode, Long> {

    Optional<OAuthAuthorizationCode> findByCodeHash(String codeHash);

    /**
     * Claim this code for the current exchange, atomically. Returns 1 if this
     * caller won it, 0 if it was already spent.
     *
     * <p>The {@code usedAt is null} predicate is the whole point, and it has to
     * live in the statement rather than in Java. Reading the row, testing
     * {@code getUsedAt()} and then writing is a check-then-write race: under
     * READ COMMITTED two concurrent exchanges both see the code unused, both
     * pass the test, and the second UPDATE overwrites the first — it never
     * re-evaluates a condition that was only ever evaluated against a stale
     * snapshot. Both callers walk away with tokens.
     *
     * <p>That mattered more than the usual version of this bug because of what
     * it defeated. Replay detection here revokes the entire token family the
     * first exchange issued; an attacker racing the legitimate client got
     * tokens <em>and</em> left the family alive, so the victim's login
     * succeeded and no alarm fired. The containment was strongest against a
     * slow attacker and absent against a fast one. B-OIDC-6, from the
     * 2026-09-14 review.
     */
    @Modifying
    @Query("update OAuthAuthorizationCode c set c.usedAt = :now "
         + "where c.id = :id and c.usedAt is null")
    int claim(@Param("id") Long id, @Param("now") LocalDateTime now);
}
