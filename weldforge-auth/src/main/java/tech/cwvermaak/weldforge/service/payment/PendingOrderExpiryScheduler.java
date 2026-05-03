package tech.cwvermaak.weldforge.service.payment;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

/**
 * Releases slug reservations for unpaid orders that sat in
 * {@code CREATED} or {@code CHECKOUT_STARTED} past the 10-minute TTL.
 * Once transitioned to {@code EXPIRED} the partial unique index no
 * longer covers the row and another customer may reserve the slug.
 *
 * <p>Short fixed-delay (60 s) because the TTL itself is only 10 min —
 * bigger drift would block slug retries for another customer.
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class PendingOrderExpiryScheduler {

    private final OrderService orderService;

    @Scheduled(fixedDelayString = "${app.payment.expiry-scan-interval-ms:60000}")
    public void expire() {
        int expired = orderService.expireStaleCheckouts();
        if (expired > 0) {
            log.info("Expired {} pending orders past their slug-reservation TTL", expired);
        }
    }
}
