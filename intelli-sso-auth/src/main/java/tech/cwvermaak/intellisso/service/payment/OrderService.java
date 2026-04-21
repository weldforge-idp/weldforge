package tech.cwvermaak.intellisso.service.payment;

import jakarta.persistence.EntityNotFoundException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import tech.cwvermaak.intellisso.model.dto.payment.CreateOrderRequest;
import tech.cwvermaak.intellisso.model.dto.payment.CreateOrderResponse;
import tech.cwvermaak.intellisso.model.payment.*;
import tech.cwvermaak.intellisso.repository.BillingTransactionRepository;
import tech.cwvermaak.intellisso.repository.PendingOrderRepository;
import tech.cwvermaak.intellisso.service.payment.gateway.GatewayCredentials;
import tech.cwvermaak.intellisso.service.payment.gateway.PaymentGatewayStrategy;

import java.security.SecureRandom;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.EnumMap;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;

/**
 * Owns the {@link OrderStatus} state machine. Every transition is
 * persisted here — no other service mutates {@code pending_orders}.
 *
 * <p>Key invariant: the {@code tenants} row is <em>never</em> created
 * before {@link #markPaid} runs. Slug reservation is enforced by the
 * partial unique DB index {@code pending_orders_active_slug_reservation};
 * a concurrent attempt to reserve the same slug surfaces as a
 * {@link DataIntegrityViolationException} which we translate to a
 * user-visible conflict.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class OrderService {

    private final PendingOrderRepository pendingOrderRepository;
    private final BillingTransactionRepository billingTransactionRepository;
    private final PaymentRoutingService routingService;
    private final Map<GatewayProvider, PaymentGatewayStrategy> strategies;

    @Value("${app.payment.slug-reservation-minutes:10}")
    private int slugReservationMinutes;

    @Value("${app.payment.checkout-success-url:https://www.weldforge.org/order-success.html}")
    private String successUrl;

    @Value("${app.payment.checkout-cancel-url:https://www.weldforge.org/order-cancelled.html}")
    private String cancelUrl;

    private static final SecureRandom RNG = new SecureRandom();

    // ---- Spring auto-assembly for {provider -> strategy} ------------

    public OrderService(PendingOrderRepository pendingOrderRepository,
                        BillingTransactionRepository billingTransactionRepository,
                        PaymentRoutingService routingService,
                        List<PaymentGatewayStrategy> strategyBeans) {
        this.pendingOrderRepository = pendingOrderRepository;
        this.billingTransactionRepository = billingTransactionRepository;
        this.routingService = routingService;
        this.strategies = new EnumMap<>(GatewayProvider.class);
        for (PaymentGatewayStrategy s : strategyBeans) {
            this.strategies.put(s.provider(), s);
        }
    }

    // ---- CREATED + CHECKOUT_STARTED --------------------------------

    @Transactional
    public CreateOrderResponse createOrder(CreateOrderRequest req) {
        long amountCents = TierPricing.amountCents(req.getTier(), req.getBillingCycle(), req.getCurrency());

        List<PaymentRoutingService.Quote> quotes = routingService.rankPlatform(
                amountCents, req.getCurrency(), req.getBillingCountry(), /* cardCountry */ null);
        if (quotes.isEmpty()) {
            throw new IllegalStateException(
                    "No payment gateway is configured for currency=" + req.getCurrency()
                            + " country=" + req.getBillingCountry());
        }
        PaymentGateway chosen = quotes.get(0).gateway();
        PaymentGatewayStrategy strategy = requireStrategy(chosen.getProvider());

        String token = newOrderToken();
        LocalDateTime slugExpires = LocalDateTime.now().plusMinutes(slugReservationMinutes);

        PendingOrder order = PendingOrder.builder()
                .orderToken(token)
                .tier(req.getTier())
                .organisation(req.getOrganisation())
                .contactName(req.getContactName())
                .contactEmail(req.getContactEmail())
                .requestedTenantSlug(req.getTenantSlug())
                .region(req.getRegion())
                .billingCycle(req.getBillingCycle() == null ? "MONTHLY" : req.getBillingCycle())
                .currency(req.getCurrency().toUpperCase())
                .amountCents(amountCents)
                .selectedGateway(chosen)
                .status(OrderStatus.CREATED)
                .slugReservationExpires(slugExpires)
                .build();

        try {
            order = pendingOrderRepository.saveAndFlush(order);
        } catch (DataIntegrityViolationException e) {
            throw new IllegalArgumentException(
                    "The slug '" + req.getTenantSlug() + "' is already reserved or in use.");
        }

        GatewayCredentials creds = GatewayCredentials.decode(chosen.getCredentialsEncrypted());
        PaymentGatewayStrategy.CheckoutRequest checkoutReq = new PaymentGatewayStrategy.CheckoutRequest(
                token,
                req.getTier(),
                req.getOrganisation(),
                req.getContactEmail(),
                amountCents,
                req.getCurrency().toUpperCase(),
                order.getBillingCycle(),
                successUrl + "?token=" + token,
                cancelUrl  + "?token=" + token,
                Map.of("orderToken", token,
                       "tier",       req.getTier(),
                       "tenantSlug", req.getTenantSlug()));

        PaymentGatewayStrategy.CheckoutResult result = strategy.createCheckout(creds, checkoutReq);

        order.setGatewaySessionId(result.gatewaySessionId());
        order.setGatewayCustomerId(result.gatewayCustomerId());
        order.setStatus(OrderStatus.CHECKOUT_STARTED);
        pendingOrderRepository.save(order);

        return CreateOrderResponse.builder()
                .orderToken(token)
                .checkoutUrl(result.checkoutUrl())
                .gatewayProvider(chosen.getProvider().name())
                .amountCents(amountCents)
                .currency(order.getCurrency())
                .slugReservationExpiresInSeconds(Duration.between(LocalDateTime.now(), slugExpires).toSeconds())
                .build();
    }

    // ---- PAID ------------------------------------------------------

    @Transactional
    public PendingOrder markPaid(String orderToken, PaymentGatewayStrategy.NormalisedEvent event) {
        PendingOrder order = pendingOrderRepository.findByOrderToken(orderToken)
                .orElseThrow(() -> new EntityNotFoundException("Unknown order token: " + orderToken));

        // Idempotency: if we already recorded this gateway_transaction_id,
        // no-op. The unique index on billing_transactions is the final
        // guard but this shortcut avoids a gratuitous second provisioning
        // attempt when webhooks retry.
        if (event.gatewayTransactionId() != null
                && billingTransactionRepository
                        .findByGatewayIdAndGatewayTransactionId(order.getSelectedGateway().getId(),
                                                                 event.gatewayTransactionId())
                        .isPresent()) {
            log.info("Duplicate PAID webhook for order {} tx {} — ignored", orderToken, event.gatewayTransactionId());
            return order;
        }

        if (order.getStatus() == OrderStatus.PROVISIONED
                || order.getStatus() == OrderStatus.REFUNDED) {
            return order;
        }
        if (order.getStatus() != OrderStatus.CHECKOUT_STARTED
                && order.getStatus() != OrderStatus.PAID) {
            throw new IllegalStateException(
                    "Cannot mark PAID from status " + order.getStatus() + " on order " + orderToken);
        }

        order.setStatus(OrderStatus.PAID);
        order.setPaidAt(LocalDateTime.now());
        pendingOrderRepository.save(order);

        BillingTransaction tx = BillingTransaction.builder()
                .pendingOrder(order)
                .gateway(order.getSelectedGateway())
                .gatewayTransactionId(event.gatewayTransactionId())
                .amountCents(event.amountCents() != null ? event.amountCents() : order.getAmountCents())
                .currency(event.currency() != null ? event.currency() : order.getCurrency())
                .status(TransactionStatus.SUCCEEDED)
                .cardCountry(event.cardCountry())
                .bin(event.bin())
                .completedAt(LocalDateTime.now())
                .build();
        billingTransactionRepository.save(tx);

        return order;
    }

    // ---- CANCELLED / EXPIRED ---------------------------------------

    @Transactional
    public void markCancelled(String orderToken) {
        pendingOrderRepository.findByOrderToken(orderToken).ifPresent(order -> {
            if (order.getStatus().isTerminal()) return;
            order.setStatus(OrderStatus.CANCELLED);
            pendingOrderRepository.save(order);
        });
    }

    @Transactional
    public int expireStaleCheckouts() {
        LocalDateTime now = LocalDateTime.now();
        List<PendingOrder> stale = new java.util.ArrayList<>(pendingOrderRepository
                .findByStatusAndSlugReservationExpiresBefore(OrderStatus.CHECKOUT_STARTED, now));
        stale.addAll(pendingOrderRepository
                .findByStatusAndSlugReservationExpiresBefore(OrderStatus.CREATED, now));
        for (PendingOrder o : stale) {
            o.setStatus(OrderStatus.EXPIRED);
        }
        pendingOrderRepository.saveAll(stale);
        return stale.size();
    }

    // ---- PROVISIONED / PROVISIONING_FAILED / REFUNDED --------------

    @Transactional
    public void markProvisioned(Long orderId, Long tenantId) {
        PendingOrder order = pendingOrderRepository.findById(orderId)
                .orElseThrow(() -> new EntityNotFoundException("Unknown order: " + orderId));
        order.setStatus(OrderStatus.PROVISIONED);
        order.setProvisionedAt(LocalDateTime.now());
        order.setLastProvisioningError(null);
        // we set provisionedTenant id via reference lookup in the provisioning
        // service; skip touching the relation from here to avoid a fresh load
        pendingOrderRepository.save(order);
    }

    @Transactional
    public void markProvisioningFailed(Long orderId, String reason) {
        PendingOrder order = pendingOrderRepository.findById(orderId)
                .orElseThrow(() -> new EntityNotFoundException("Unknown order: " + orderId));
        order.setStatus(OrderStatus.PROVISIONING_FAILED);
        order.setProvisioningAttempts(order.getProvisioningAttempts() + 1);
        order.setLastProvisioningError(reason);
        pendingOrderRepository.save(order);
    }

    @Transactional
    public void markRefunded(Long orderId) {
        PendingOrder order = pendingOrderRepository.findById(orderId)
                .orElseThrow(() -> new EntityNotFoundException("Unknown order: " + orderId));
        order.setStatus(OrderStatus.REFUNDED);
        pendingOrderRepository.save(order);
    }

    // ---- Helpers ---------------------------------------------------

    private PaymentGatewayStrategy requireStrategy(GatewayProvider provider) {
        PaymentGatewayStrategy s = strategies.get(provider);
        if (s == null) {
            throw new IllegalStateException("No PaymentGatewayStrategy bean for provider " + provider);
        }
        return s;
    }

    private static String newOrderToken() {
        byte[] buf = new byte[24];
        RNG.nextBytes(buf);
        return "wfo_" + HexFormat.of().formatHex(buf);
    }
}
