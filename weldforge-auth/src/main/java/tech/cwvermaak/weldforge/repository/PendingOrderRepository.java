package tech.cwvermaak.weldforge.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import tech.cwvermaak.weldforge.model.payment.OrderStatus;
import tech.cwvermaak.weldforge.model.payment.PendingOrder;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

public interface PendingOrderRepository extends JpaRepository<PendingOrder, Long> {

    Optional<PendingOrder> findByOrderToken(String orderToken);

    Optional<PendingOrder> findByGatewaySessionId(String gatewaySessionId);

    List<PendingOrder> findByStatusAndSlugReservationExpiresBefore(OrderStatus status, LocalDateTime cutoff);

    List<PendingOrder> findByStatus(OrderStatus status);

    /**
     * Retry budget query: PROVISIONING_FAILED rows that still have time left
     * on the 24-hour retry budget. The budget start is {@code paidAt}; the
     * scheduler computes the cutoff.
     */
    List<PendingOrder> findByStatusAndPaidAtAfter(OrderStatus status, LocalDateTime cutoff);
}
