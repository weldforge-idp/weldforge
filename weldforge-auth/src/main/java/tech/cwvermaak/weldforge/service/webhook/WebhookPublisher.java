package tech.cwvermaak.weldforge.service.webhook;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import tech.cwvermaak.weldforge.model.Tenant;
import tech.cwvermaak.weldforge.model.WebhookDelivery;
import tech.cwvermaak.weldforge.model.WebhookSubscription;
import tech.cwvermaak.weldforge.repository.WebhookDeliveryRepository;
import tech.cwvermaak.weldforge.repository.WebhookSubscriptionRepository;

import java.time.LocalDateTime;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Publishes lifecycle events to matching {@link WebhookSubscription}s
 * (PRD API-05). For every matching enabled subscription a
 * {@link WebhookDelivery} row is persisted and a synchronous first attempt
 * is made; failures hand off to the retry scheduler.
 *
 * <p>Matching rules: if the subscription has no filters every event
 * matches. Otherwise the event type must match at least one filter glob;
 * {@code *} is the only wildcard supported and may appear as a trailing
 * segment (e.g. {@code user.*} matches {@code user.create}).
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class WebhookPublisher {

    private final WebhookSubscriptionRepository subscriptionRepository;
    private final WebhookDeliveryRepository deliveryRepository;
    private final WebhookHttpClient httpClient;
    private final ObjectMapper objectMapper;

    /**
     * Fire-and-forget publish. Never throws — webhook delivery is a
     * side-effect of the primary operation (a login, a role change) and
     * must never roll it back.
     */
    @Transactional
    public void publish(String eventType, Tenant tenant, Map<String, Object> data) {
        if (tenant == null || eventType == null) return;
        try {
            List<WebhookSubscription> subs =
                    subscriptionRepository.findByTenantIdAndEnabledTrue(tenant.getId());
            if (subs.isEmpty()) return;

            String eventId = UUID.randomUUID().toString();
            Map<String, Object> envelope = envelope(eventId, eventType, tenant, data);
            String body;
            try {
                body = objectMapper.writeValueAsString(envelope);
            } catch (JsonProcessingException e) {
                log.warn("Failed to serialise webhook payload for event {}: {}", eventType, e.getMessage());
                return;
            }

            long timestamp = System.currentTimeMillis() / 1000;
            for (WebhookSubscription sub : subs) {
                if (!matches(sub, eventType)) continue;
                String sig = WebhookSigner.sign(sub.getSecret(), timestamp, body);
                String header = WebhookSigner.header(timestamp, sig);

                WebhookDelivery delivery = WebhookDelivery.builder()
                        .subscription(sub)
                        .tenant(tenant)
                        .eventType(eventType)
                        .eventId(eventId)
                        .payloadJson(body)
                        .signature(sig)
                        .status(WebhookDelivery.Status.PENDING)
                        .attemptCount(0)
                        .nextAttemptAt(LocalDateTime.now())
                        .build();
                delivery = deliveryRepository.save(delivery);
                attemptDelivery(delivery, header);
            }
        } catch (Exception e) {
            log.warn("Webhook publish for event {} failed: {}", eventType, e.getMessage());
        }
    }

    /**
     * Try to deliver the row once. On success, mark SUCCESS. On retryable
     * failure, bump attempt count and schedule next retry with
     * exponential backoff. On non-retryable failure, mark FAILED.
     */
    @Transactional
    public void attemptDelivery(WebhookDelivery delivery, String signatureHeader) {
        WebhookSubscription sub = delivery.getSubscription();
        WebhookHttpClient.Result result = httpClient.post(sub.getTargetUrl(), delivery.getPayloadJson(), signatureHeader);

        delivery.setAttemptCount(delivery.getAttemptCount() + 1);
        delivery.setLastResponseCode(result.statusCode() == 0 ? null : result.statusCode());
        delivery.setLastError(result.error());

        if (result.isSuccess()) {
            delivery.setStatus(WebhookDelivery.Status.SUCCESS);
            delivery.setDeliveredAt(LocalDateTime.now());
            delivery.setNextAttemptAt(null);
        } else if (!result.isRetryable()) {
            delivery.setStatus(WebhookDelivery.Status.FAILED);
            delivery.setNextAttemptAt(null);
        } else if (delivery.getAttemptCount() >= sub.getMaxAttempts()) {
            delivery.setStatus(WebhookDelivery.Status.DEAD_LETTER);
            delivery.setNextAttemptAt(null);
        } else {
            delivery.setStatus(WebhookDelivery.Status.PENDING);
            delivery.setNextAttemptAt(nextBackoff(delivery.getAttemptCount()));
        }
        deliveryRepository.save(delivery);
    }

    static LocalDateTime nextBackoff(int attempt) {
        // 30s, 2m, 10m, 1h, 6h — then capped at 6h for any further retries.
        long[] schedule = {30, 120, 600, 3600, 21600};
        long seconds = schedule[Math.min(attempt - 1, schedule.length - 1)];
        return LocalDateTime.now().plusSeconds(seconds);
    }

    static boolean matches(WebhookSubscription sub, String eventType) {
        List<String> filters = sub.getEventFilters();
        if (filters == null || filters.isEmpty()) return true;
        for (String f : filters) {
            if (f == null) continue;
            if (f.equals("*")) return true;
            if (f.endsWith(".*")) {
                String prefix = f.substring(0, f.length() - 1); // keep trailing dot
                if (eventType.startsWith(prefix)) return true;
            } else if (f.equals(eventType)) {
                return true;
            }
        }
        return false;
    }

    private static Map<String, Object> envelope(String eventId, String eventType, Tenant tenant, Map<String, Object> data) {
        Map<String, Object> envelope = new LinkedHashMap<>();
        envelope.put("id", eventId);
        envelope.put("type", eventType);
        envelope.put("tenant", tenant.getSlug());
        envelope.put("tenant_id", tenant.getId());
        envelope.put("timestamp", System.currentTimeMillis() / 1000);
        envelope.put("data", data == null ? Map.of() : data);
        return envelope;
    }
}
