package tech.cwvermaak.weldforge.service.mfa;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.javacrumbs.shedlock.spring.annotation.SchedulerLock;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;
import tech.cwvermaak.weldforge.repository.ConsumedMfaChallengeRepository;

import java.time.LocalDateTime;

/**
 * Prunes spent MFA challenge tokens (B-MFA-2) once they have expired. Rows are
 * only needed while the challenge token is still within its ~5-minute validity
 * window; after that the signature check alone rejects it, so the row is dead
 * weight. Runs hourly by default.
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class ConsumedMfaChallengeCleanup {

    private final ConsumedMfaChallengeRepository repository;

    // Cluster-wide single execution. A row delete; short work, hourly cadence.
    @Scheduled(fixedDelayString = "${app.mfa.challenge-cleanup-interval-ms:3600000}")
    @SchedulerLock(name = "consumedMfaChallengeCleanup", lockAtMostFor = "PT5M", lockAtLeastFor = "PT1M")
    @Transactional
    public void purgeExpired() {
        long removed = repository.deleteByExpiresAtBefore(LocalDateTime.now());
        if (removed > 0) {
            log.debug("Pruned {} expired consumed-MFA-challenge rows", removed);
        }
    }
}
