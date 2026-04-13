package tech.cwvermaak.intellisso.service.oidc;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import tech.cwvermaak.intellisso.model.Tenant;
import tech.cwvermaak.intellisso.model.TenantSigningKey;
import tech.cwvermaak.intellisso.repository.TenantRepository;
import tech.cwvermaak.intellisso.repository.TenantSigningKeyRepository;

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

    @Scheduled(fixedDelayString = "${app.key-rotation.interval-ms:86400000}")
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
