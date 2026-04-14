package tech.cwvermaak.intellisso.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import tech.cwvermaak.intellisso.model.WebhookSubscription;

import java.util.List;
import java.util.Optional;

public interface WebhookSubscriptionRepository extends JpaRepository<WebhookSubscription, Long> {

    List<WebhookSubscription> findByTenantId(Long tenantId);

    List<WebhookSubscription> findByTenantIdAndEnabledTrue(Long tenantId);

    Optional<WebhookSubscription> findByIdAndTenantId(Long id, Long tenantId);
}
