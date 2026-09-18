package tech.cwvermaak.weldforge.service.security;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.javacrumbs.shedlock.spring.annotation.SchedulerLock;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;
import tech.cwvermaak.weldforge.repository.RefreshTokenRepository;

import java.time.LocalDateTime;

/**
 * Deletes expired refresh-token rows (B-PRIV-1).
 *
 * <p>Rotation mints a successor on every refresh and marks its predecessor
 * used, so {@code refresh_tokens} gained one row per refresh and never lost
 * one. It is the fastest-growing table in the schema, and its rows carry an IP
 * address and user agent — so unbounded retention is a privacy question as much
 * as an operational one. {@code docs/compliance/privacy-and-data-retention.md}
 * proposed a schedule and recorded that no purge job existed for any category.
 * This is the first of them.
 *
 * <p><strong>Revoked rows are deliberately never deleted here.</strong> See
 * {@link RefreshTokenRepository#purgeExpiredUnrevoked} — briefly,
 * {@code JwtAuthenticationFilter} decides whether a session was terminated by
 * asking whether the family has a revoked row, and reads absence as "still
 * live". Purging them would quietly resurrect logged-out sessions. They are
 * also a tiny fraction of the volume, so excluding them costs nothing.
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class RefreshTokenPurgeScheduler {

    private final RefreshTokenRepository repository;
    private final RefreshTokenProperties properties;

    // Cluster-wide single execution. Daily at 03:40, offset from the 02:15
    // Postgres backup so a large delete does not run inside the dump window.
    @Scheduled(cron = "${app.security.refresh-token.purge-cron:0 40 3 * * *}")
    @SchedulerLock(name = "refreshTokenPurge", lockAtMostFor = "PT30M", lockAtLeastFor = "PT1M")
    @Transactional
    public void purge() {
        LocalDateTime cutoff = LocalDateTime.now().minusDays(properties.getPurgeAfterExpiryDays());
        int deleted = repository.purgeExpiredUnrevoked(cutoff);
        if (deleted > 0) {
            // INFO, not DEBUG: this is the only record that data was destroyed,
            // and a retention policy nobody can evidence is not a policy.
            log.info("Purged {} refresh-token row(s) expired before {} (revoked rows retained)",
                     deleted, cutoff);
        }
    }
}
