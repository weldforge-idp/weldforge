package tech.cwvermaak.weldforge.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
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
}
