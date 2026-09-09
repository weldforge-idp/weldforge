package tech.cwvermaak.weldforge.service.saml;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;
import tech.cwvermaak.weldforge.repository.SamlRequestReplayRepository;

import java.time.LocalDateTime;

/**
 * Prunes AuthnRequest IDs past their freshness window (CONF-5.3).
 *
 * <p>A request older than the window is refused on freshness grounds anyway, so
 * the row no longer carries information. Mirrors the cleanup jobs for consumed
 * MFA challenges and WebAuthn ceremonies.
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class SamlRequestReplayCleanup {

    private final SamlRequestReplayRepository repository;

    @Scheduled(fixedDelayString = "${app.saml.replay-cleanup-interval-ms:3600000}")
    @Transactional
    public void purgeExpired() {
        long removed = repository.deleteByExpiresAtBefore(LocalDateTime.now());
        if (removed > 0) {
            log.debug("Pruned {} expired SAML request-replay rows", removed);
        }
    }
}
