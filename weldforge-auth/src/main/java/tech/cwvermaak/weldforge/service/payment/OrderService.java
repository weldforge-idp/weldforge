package tech.cwvermaak.weldforge.service.payment;

import jakarta.persistence.EntityNotFoundException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import tech.cwvermaak.weldforge.model.dto.payment.CreateOrderRequest;
import tech.cwvermaak.weldforge.model.dto.payment.CreateOrderResponse;
import tech.cwvermaak.weldforge.model.payment.*;
import tech.cwvermaak.weldforge.repository.BillingTransactionRepository;
import tech.cwvermaak.weldforge.repository.PendingOrderRepository;
import tech.cwvermaak.weldforge.service.TenantSlugValidator;
import tech.cwvermaak.weldforge.service.payment.gateway.GatewayCredentials;
import tech.cwvermaak.weldforge.service.payment.gateway.PaymentGatewayStrategy;
import tech.cwvermaak.weldforge.service.mail.MailService;

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
@Slf4j
public class OrderService {

    private final PendingOrderRepository pendingOrderRepository;
    private final BillingTransactionRepository billingTransactionRepository;
    private final PaymentRoutingService routingService;
    private final TenantSlugValidator slugValidator;
    private final MailService mailService;
    private final Map<GatewayProvider, PaymentGatewayStrategy> strategies;

    // Field initialisers, not just @Value defaults. This service is also
    // constructed directly (the BDD harness does), and a @Value field on a
    // hand-built instance is left at 0 -- which silently made a "reserved"
    // slug expire the instant it was created.
    @Value("${app.payment.slug-reservation-minutes:10}")
    private int slugReservationMinutes = 10;

    @Value("${app.payment.checkout-success-url:https://www.weldforge.org/order-success.html}")
    private String successUrl;

    @Value("${app.payment.checkout-cancel-url:https://www.weldforge.org/order-cancelled.html}")
    private String cancelUrl;

    /** How long a slug stays reserved when the order needs a human, not a card. */
    @Value("${app.payment.manual-followup-reservation-hours:72}")
    private int manualFollowUpReservationHours = 72;

    @Value("${app.payment.sales-email:sales@weldforge.org}")
    private String salesEmail = "sales@weldforge.org";

    private static final SecureRandom RNG = new SecureRandom();

    // ---- Spring auto-assembly for {provider -> strategy} ------------

    public OrderService(PendingOrderRepository pendingOrderRepository,
                        BillingTransactionRepository billingTransactionRepository,
                        PaymentRoutingService routingService,
                        TenantSlugValidator slugValidator,
                        MailService mailService,
                        List<PaymentGatewayStrategy> strategyBeans) {
        this.pendingOrderRepository = pendingOrderRepository;
        this.billingTransactionRepository = billingTransactionRepository;
        this.routingService = routingService;
        this.slugValidator = slugValidator;
        this.mailService = mailService;
        this.strategies = new EnumMap<>(GatewayProvider.class);
        for (PaymentGatewayStrategy s : strategyBeans) {
            this.strategies.put(s.provider(), s);
        }
    }

    // ---- CREATED + CHECKOUT_STARTED --------------------------------

    @Transactional
    public CreateOrderResponse createOrder(CreateOrderRequest req) {
        // B-PROV-1: validate + normalise the requested slug with the SAME rules
        // the admin path uses (reserved labels, holdback, format) — fail fast
        // (400) before reserving the slug or starting a checkout.
        String slug = slugValidator.validate(req.getTenantSlug());
        long amountCents = TierPricing.amountCents(req.getTier(), req.getBillingCycle(), req.getCurrency());

        List<PaymentRoutingService.Quote> quotes = routingService.rankPlatform(
                amountCents, req.getCurrency(), req.getBillingCountry(), /* cardCountry */ null);

        // No gateway configured is a normal state for this platform, not an
        // error: the operator may not have a merchant account yet. It used to
        // throw here, BEFORE the order row was written, so a prospective
        // customer filled in the form, got a 500, and left no trace at all --
        // the funnel silently discarded every lead it was built to capture.
        //
        // Record the order either way. With a gateway we start a checkout as
        // before; without one the order rests in CREATED and a human follows up.
        boolean canCheckOut = !quotes.isEmpty();
        PaymentGateway chosen = canCheckOut ? quotes.get(0).gateway() : null;

        String token = newOrderToken();
        // A slug held for 10 minutes makes sense while a card is being typed.
        // It does not survive a human replying to an email, so the manual path
        // holds it long enough for that conversation to happen.
        LocalDateTime slugExpires = canCheckOut
                ? LocalDateTime.now().plusMinutes(slugReservationMinutes)
                : LocalDateTime.now().plusHours(manualFollowUpReservationHours);

        PendingOrder order = PendingOrder.builder()
                .orderToken(token)
                .tier(req.getTier())
                .organisation(req.getOrganisation())
                .contactName(req.getContactName())
                .contactEmail(req.getContactEmail())
                .requestedTenantSlug(slug)
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

        if (!canCheckOut) {
            // The lead is now durable. Tell the operator it arrived, and tell
            // the caller plainly that there is no checkout to redirect to --
            // a null checkoutUrl with no explanation is how a front-end ends up
            // redirecting to "undefined".
            notifySalesOfManualOrder(order);
            log.info("Order {} recorded for manual follow-up: no gateway for currency={} country={}",
                     token, req.getCurrency(), req.getBillingCountry());
            return CreateOrderResponse.builder()
                    .orderToken(token)
                    .checkoutUrl(null)
                    .nextStep(CreateOrderResponse.NextStep.MANUAL_FOLLOW_UP)
                    .gatewayProvider(null)
                    .amountCents(amountCents)
                    .currency(order.getCurrency())
                    .slugReservationExpiresInSeconds(
                            Duration.between(LocalDateTime.now(), slugExpires).toSeconds())
                    .build();
        }

        PaymentGatewayStrategy strategy = requireStrategy(chosen.getProvider());

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
                       "tenantSlug", slug));

        PaymentGatewayStrategy.CheckoutResult result = strategy.createCheckout(creds, checkoutReq);

        order.setGatewaySessionId(result.gatewaySessionId());
        order.setGatewayCustomerId(result.gatewayCustomerId());
        order.setStatus(OrderStatus.CHECKOUT_STARTED);
        pendingOrderRepository.save(order);

        return CreateOrderResponse.builder()
                .orderToken(token)
                .checkoutUrl(result.checkoutUrl())
                .nextStep(CreateOrderResponse.NextStep.CHECKOUT)
                .gatewayProvider(chosen.getProvider().name())
                .amountCents(amountCents)
                .currency(order.getCurrency())
                .slugReservationExpiresInSeconds(Duration.between(LocalDateTime.now(), slugExpires).toSeconds())
                .build();
    }

    /**
     * Tells the operator a sign-up is waiting. Best-effort on purpose: the
     * order row is already committed, and failing the caller's request because
     * a notification could not be sent would throw away the lead we just went
     * to some trouble to keep.
     */
    private void notifySalesOfManualOrder(PendingOrder order) {
        String subject = "New WeldForge sign-up: " + order.getOrganisation()
                + " (" + order.getTier() + ")";
        String body = String.join(System.lineSeparator(),
                "A hosted sign-up was submitted and is waiting for a human.",
                "",
                "Organisation : " + order.getOrganisation(),
                "Contact      : " + order.getContactName() + " <" + order.getContactEmail() + ">",
                "Tier         : " + order.getTier() + " (" + order.getBillingCycle() + ")",
                "Requested slug: " + order.getRequestedTenantSlug(),
                "Region       : " + order.getRegion(),
                "Amount       : " + order.getAmountCents() + " " + order.getCurrency() + " (cents)",
                "Order token  : " + order.getOrderToken(),
                "",
                "No payment gateway is configured for this currency/country, so no",
                "checkout was started. The slug is reserved until "
                        + order.getSlugReservationExpires() + ".",
                "",
                "Configure a gateway (POST /api/admin/payment-gateways) to make this",
                "path self-serve.");
        try {
            mailService.send(salesEmail, subject, body);
        } catch (Exception e) {
            log.error("Could not notify {} about order {}: {}", salesEmail, order.getOrderToken(), e.toString());
        }
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
