package tech.cwvermaak.weldforge.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import tech.cwvermaak.weldforge.model.ConsumedMfaChallenge;

import java.time.LocalDateTime;

public interface ConsumedMfaChallengeRepository extends JpaRepository<ConsumedMfaChallenge, String> {

    /** Prune rows whose token has already expired. */
    long deleteByExpiresAtBefore(LocalDateTime cutoff);
}
