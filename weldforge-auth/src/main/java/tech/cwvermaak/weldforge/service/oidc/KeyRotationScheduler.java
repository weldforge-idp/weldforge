package tech.cwvermaak.weldforge.service.oidc;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import net.javacrumbs.shedlock.spring.annotation.SchedulerLock;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import tech.cwvermaak.weldforge.model.Tenant;
import tech.cwvermaak.weldforge.model.TenantSigningKey;
import tech.cwvermaak.weldforge.repository.TenantRepository;
import tech.cwvermaak.weldforge.repository.TenantSigningKeyRepository;

import java.time.LocalDateTime;
import java.util.List;

/**
 * Scheduled task that rotates tenant signing keys whose active key is
 * older than the configured maximum age. Opt-in via
 * {@code app.key-rotation.enabled=true}.
 */
@Component
@ConditionalOnProperty(name = "app.key-rotation.enabled", havingValue = "true", matchIfMissing = false)
@RequiredArgsConstructor
@Slf4j
public class KeyRotationScheduler {

    private final TenantSigningKeyService signingKeyService;
    private final TenantSigningKeyRepository signingKeyRepository;
    private final TenantRepository tenantRepository;

    @Value("${app.key-rotation.max-age-days:90}")
    private long maxAgeDays;

    // Cluster-wide single execution. Two instances rotating a tenant signing key
    // at the same moment is the worst case in this file: relying parties would be
    // validating against a JWKS that changed twice. lockAtLeastFor is generous so
    // a fast no-op run cannot release the lease in time for a second instance to
    // pick the same window up.
    @Scheduled(fixedDelayString = "${app.key-rotation.interval-ms:86400000}")
    @SchedulerLock(name = "keyRotation", lockAtMostFor = "PT15M", lockAtLeastFor = "PT5M")
    public void checkAndRotateKeys() {
        log.info("Key rotation check started (max-age-days={})", maxAgeDays);

        List<Tenant> tenants = tenantRepository.findAll();
        int rotated = 0;

        for (Tenant tenant : tenants) {
            try {
                var activeKey = signingKeyRepository.findFirstByTenantIdAndActiveTrue(tenant.getId());
                if (activeKey.isEmpty()) {
                    log.debug("Tenant {} has no active signing key — skipping", tenant.getSlug());
                    continue;
                }

                TenantSigningKey key = activeKey.get();
                LocalDateTime threshold = LocalDateTime.now().minusDays(maxAgeDays);

                if (key.getCreatedAt() != null && key.getCreatedAt().isBefore(threshold)) {
                    log.info("Rotating signing key for tenant {} (kid={}, created={})",
                            tenant.getSlug(), key.getKid(), key.getCreatedAt());
                    signingKeyService.rotate(tenant);
                    rotated++;
                }
            } catch (Exception e) {
                log.error("Failed to check/rotate key for tenant {}: {}",
                        tenant.getSlug(), e.getMessage(), e);
            }
        }

        log.info("Key rotation check completed — {} key(s) rotated across {} tenant(s)",
                rotated, tenants.size());
    }
}
