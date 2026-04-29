package tech.cwvermaak.intellisso.service.pki;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import tech.cwvermaak.intellisso.model.AuditEvent;
import tech.cwvermaak.intellisso.model.IssuedCertificate;
import tech.cwvermaak.intellisso.repository.IssuedCertificateRepository;
import tech.cwvermaak.intellisso.service.audit.AuditEventTypes;
import tech.cwvermaak.intellisso.service.audit.AuditService;

import java.time.LocalDateTime;
import java.util.List;

/**
 * Daily scan for issued certificates approaching expiry (PRD X50-04).
 *
 * <p>Checks four "advance notice" windows — 30, 14, 7 and 1 days before
 * expiry — and emits a {@link AuditEventTypes#PKI_CERT_EXPIRING} audit
 * event for each hit. Because {@link AuditService} automatically fans
 * audit events out to the tenant's webhook subscriptions (Epic F),
 * renewal notifications ride for free on the existing delivery machinery
 * — no dedicated email path required here.
 *
 * <p>Each window is a 24-hour band so the scheduler only fires once per
 * certificate per window even though it runs every 12 hours.
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class CertificateRenewalNotifier {

    private static final int[] WINDOWS_DAYS = {30, 14, 7, 1};

    private final IssuedCertificateRepository repository;
    private final AuditService auditService;

    @Scheduled(cron = "${app.pki.renewal-scan-cron:0 0 6 * * *}")
    public void scan() {
        LocalDateTime now = LocalDateTime.now();
        for (int window : WINDOWS_DAYS) {
            LocalDateTime from = now.plusDays(window);
            LocalDateTime to = from.plusDays(1);
            List<IssuedCertificate> expiring = repository
                    .findByStatusAndExpiresAtBetween(IssuedCertificate.Status.ACTIVE, from, to);
            for (IssuedCertificate cert : expiring) {
                log.info("Certificate {} expires in ~{} days", cert.getSerialNumber(), window);
                auditService.log(AuditEvent.builder()
                        .eventType(AuditEventTypes.PKI_CERT_EXPIRING)
                        .outcome(AuditEvent.Outcome.SUCCESS)
                        .tenant(cert.getTenant())
                        .targetType(AuditEventTypes.TARGET_ISSUED_CERTIFICATE)
                        .targetId(cert.getSerialNumber())
                        .metadata(AuditService.meta(
                                "days_until_expiry", window,
                                "subject", cert.getSubjectDn(),
                                "expires_at", cert.getExpiresAt().toString())));
            }
        }
    }
}
