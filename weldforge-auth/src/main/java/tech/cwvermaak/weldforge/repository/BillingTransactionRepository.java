package tech.cwvermaak.weldforge.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import tech.cwvermaak.weldforge.model.payment.BillingTransaction;

import java.util.List;
import java.util.Optional;

public interface BillingTransactionRepository extends JpaRepository<BillingTransaction, Long> {

    /**
     * Webhook idempotency key — unique per (gateway_id, gateway_transaction_id).
     * The DB unique index guarantees a second inbound webhook with the same
     * transaction id is rejected at insert time.
     */
    Optional<BillingTransaction> findByGatewayIdAndGatewayTransactionId(Long gatewayId, String gatewayTransactionId);

    List<BillingTransaction> findByPendingOrderId(Long pendingOrderId);

    List<BillingTransaction> findBySubscriptionId(Long subscriptionId);
}
