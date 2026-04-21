package tech.cwvermaak.intellisso.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import tech.cwvermaak.intellisso.model.payment.Subscription;
import tech.cwvermaak.intellisso.model.payment.SubscriptionStatus;

import java.util.List;
import java.util.Optional;

public interface SubscriptionRepository extends JpaRepository<Subscription, Long> {

    List<Subscription> findByTenantId(Long tenantId);

    List<Subscription> findByStatus(SubscriptionStatus status);

    Optional<Subscription> findByGatewaySubscriptionId(String gatewaySubscriptionId);

    Optional<Subscription> findFirstByTenantIdAndStatus(Long tenantId, SubscriptionStatus status);
}
