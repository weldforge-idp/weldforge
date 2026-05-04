package tech.cwvermaak.weldforge.service.webhook;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import tech.cwvermaak.weldforge.model.WebhookDelivery;
import tech.cwvermaak.weldforge.repository.WebhookDeliveryRepository;

import java.time.LocalDateTime;
import java.util.List;

/**
 * Runs every 30s and re-attempts any PENDING deliveries whose
 * {@code next_attempt_at} is in the past. Backoff schedule is owned by
 * {@link WebhookPublisher#nextBackoff(int)}; this class just picks rows
 * off the queue and hands them back.
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class WebhookRetryScheduler {

    private final WebhookDeliveryRepository deliveryRepository;
    private final WebhookPublisher publisher;

    @Scheduled(fixedDelayString = "${app.webhooks.retry-interval-ms:30000}")
    public void retryPending() {
        List<WebhookDelivery> due = deliveryRepository
                .findTop100ByStatusAndNextAttemptAtLessThanEqualOrderByNextAttemptAtAsc(
                        WebhookDelivery.Status.PENDING, LocalDateTime.now());
        if (due.isEmpty()) return;
        log.debug("Webhook retry scheduler picked up {} pending deliveries", due.size());

        for (WebhookDelivery d : due) {
            // Skip rows that are in their "just created, not yet retried"
            // grace window — the publisher itself handles the first attempt
            // synchronously, so a row sitting at attempt_count=0 means the
            // synchronous attempt didn't complete yet.
            if (d.getAttemptCount() == 0) continue;

            long ts = System.currentTimeMillis() / 1000;
            String header = WebhookSigner.header(ts, d.getSignature());
            try {
                publisher.attemptDelivery(d, header);
            } catch (Exception e) {
                log.warn("Retry delivery {} raised: {}", d.getId(), e.getMessage());
            }
        }
    }
}
