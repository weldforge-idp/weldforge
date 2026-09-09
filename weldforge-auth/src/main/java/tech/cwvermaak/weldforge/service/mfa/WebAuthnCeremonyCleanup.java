package tech.cwvermaak.weldforge.service.mfa;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;
import tech.cwvermaak.weldforge.repository.WebAuthnCeremonyRepository;

import java.time.LocalDateTime;

/**
 * Prunes WebAuthn ceremonies nobody finished (CONF-3.1).
 *
 * <p>Abandoning a ceremony is normal, not exceptional: the browser shows a
 * system prompt and users close the tab. The in-memory maps this replaced never
 * evicted those, so they grew until the next restart. Mirrors
 * {@link ConsumedMfaChallengeCleanup}, which solves the same problem for spent
 * MFA challenge tokens.
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class WebAuthnCeremonyCleanup {

    private final WebAuthnCeremonyRepository repository;

    @Scheduled(fixedDelayString = "${app.mfa.webauthn.ceremony-cleanup-interval-ms:3600000}")
    @Transactional
    public void purgeExpired() {
        long removed = repository.deleteByExpiresAtBefore(LocalDateTime.now());
        if (removed > 0) {
            log.debug("Pruned {} expired WebAuthn ceremony rows", removed);
        }
    }
}
