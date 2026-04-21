package tech.cwvermaak.intellisso.service.payment;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import tech.cwvermaak.intellisso.model.payment.GatewayProvider;
import tech.cwvermaak.intellisso.model.payment.GatewayScope;
import tech.cwvermaak.intellisso.model.payment.PaymentGateway;
import tech.cwvermaak.intellisso.model.payment.PendingOrder;
import tech.cwvermaak.intellisso.repository.PaymentGatewayRepository;
import tech.cwvermaak.intellisso.service.payment.gateway.GatewayCredentials;
import tech.cwvermaak.intellisso.service.payment.gateway.PaymentGatewayStrategy;

import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Receives a raw webhook payload from one of the configured gateways,
 * verifies the signature against every matching enabled gateway's
 * webhook secret (supports multiple Stripe accounts across tenants),
 * parses the event, and dispatches to {@link OrderService}.
 *
 * <p>Signature verification uses {@link PaymentGatewayStrategy#verifySignature}
 * — implementations must constant-time compare. Verification failure
 * on <em>all</em> candidate gateways is logged at WARN and the HTTP
 * response is 400, consistent with Stripe's own reference behaviour.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class WebhookService {

    private final PaymentGatewayRepository gatewayRepository;
    private final OrderService orderService;
    private final TenantProvisioningService provisioningService;
    private final Map<GatewayProvider, PaymentGatewayStrategy> strategies;

    public WebhookService(PaymentGatewayRepository gatewayRepository,
                          OrderService orderService,
                          TenantProvisioningService provisioningService,
                          List<PaymentGatewayStrategy> strategyBeans) {
        this.gatewayRepository = gatewayRepository;
        this.orderService = orderService;
        this.provisioningService = provisioningService;
        this.strategies = new EnumMap<>(GatewayProvider.class);
        for (PaymentGatewayStrategy s : strategyBeans) {
            this.strategies.put(s.provider(), s);
        }
    }

    public Result handle(GatewayProvider provider, String rawPayload, String signatureHeader) {
        PaymentGatewayStrategy strategy = strategies.get(provider);
        if (strategy == null) {
            log.warn("Webhook received for unknown provider {}", provider);
            return Result.BAD_PROVIDER;
        }

        List<PaymentGateway> candidates = gatewayRepository.findByScopeAndEnabledTrue(GatewayScope.PLATFORM).stream()
                .filter(g -> g.getProvider() == provider)
                .toList();
        if (candidates.isEmpty()) {
            log.warn("No enabled PLATFORM gateway rows for provider {}", provider);
            return Result.NO_GATEWAY_CONFIGURED;
        }

        Optional<PaymentGateway> matched = candidates.stream()
                .filter(g -> {
                    try {
                        return strategy.verifySignature(
                                GatewayCredentials.decode(g.getCredentialsEncrypted()),
                                rawPayload,
                                signatureHeader);
                    } catch (Exception e) {
                        log.debug("Signature check threw against gateway {}: {}", g.getId(), e.toString());
                        return false;
                    }
                })
                .findFirst();

        if (matched.isEmpty()) {
            return Result.SIGNATURE_INVALID;
        }

        PaymentGatewayStrategy.NormalisedEvent event = strategy.parseEvent(rawPayload);
        return dispatch(event);
    }

    private Result dispatch(PaymentGatewayStrategy.NormalisedEvent event) {
        if (event.type() == PaymentGatewayStrategy.EventType.IGNORED) {
            return Result.IGNORED;
        }
        if (event.orderToken() == null) {
            log.warn("Webhook event {} carries no orderToken — cannot match pending order", event.type());
            return Result.NO_MATCHING_ORDER;
        }

        switch (event.type()) {
            case CHECKOUT_COMPLETED, PAYMENT_SUCCEEDED -> {
                PendingOrder order = orderService.markPaid(event.orderToken(), event);
                // Skip re-provisioning on duplicate-delivery webhooks — the
                // first delivery already drove the order to PROVISIONED.
                if (order.getStatus() == tech.cwvermaak.intellisso.model.payment.OrderStatus.PROVISIONED
                        || order.getStatus() == tech.cwvermaak.intellisso.model.payment.OrderStatus.REFUNDED) {
                    return Result.ACCEPTED;
                }
                try {
                    provisioningService.provision(order.getId());
                } catch (TenantProvisioningService.ProvisioningException e) {
                    // Already audited inside provisioningService. Scheduler
                    // will retry for 24h from paidAt.
                    log.warn("Provisioning queued for retry on order {}: {}", event.orderToken(), e.getMessage());
                }
                return Result.ACCEPTED;
            }
            case CHECKOUT_CANCELLED, PAYMENT_FAILED -> {
                orderService.markCancelled(event.orderToken());
                return Result.ACCEPTED;
            }
            case PAYMENT_REFUNDED -> {
                // Handled by operator-triggered refund flow; just log for now.
                log.info("Refund event for order {}", event.orderToken());
                return Result.ACCEPTED;
            }
            case SUBSCRIPTION_RENEWED, SUBSCRIPTION_CANCELLED -> {
                // v1.5 — subscription lifecycle. No-op at v1.
                return Result.IGNORED;
            }
            default -> {
                return Result.IGNORED;
            }
        }
    }

    public enum Result {
        ACCEPTED,
        IGNORED,
        SIGNATURE_INVALID,
        BAD_PROVIDER,
        NO_GATEWAY_CONFIGURED,
        NO_MATCHING_ORDER
    }
}
