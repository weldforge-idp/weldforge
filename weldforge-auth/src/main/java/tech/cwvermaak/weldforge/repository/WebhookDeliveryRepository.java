package tech.cwvermaak.weldforge.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import tech.cwvermaak.weldforge.model.WebhookDelivery;

import java.time.LocalDateTime;
import java.util.List;

public interface WebhookDeliveryRepository extends JpaRepository<WebhookDelivery, Long> {

    List<WebhookDelivery> findBySubscriptionIdOrderByCreatedAtDesc(Long subscriptionId);

    /**
     * Retry scheduler query — pick up deliveries whose next attempt is due.
     * The {@code (status, next_attempt_at)} index keeps this cheap even as
     * the table grows.
     */
    List<WebhookDelivery> findTop100ByStatusAndNextAttemptAtLessThanEqualOrderByNextAttemptAtAsc(
            WebhookDelivery.Status status, LocalDateTime cutoff);
}
