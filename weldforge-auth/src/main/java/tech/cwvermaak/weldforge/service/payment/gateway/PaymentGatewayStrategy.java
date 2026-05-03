package tech.cwvermaak.weldforge.service.payment.gateway;

import tech.cwvermaak.weldforge.model.payment.GatewayProvider;

import java.util.Map;

/**
 * Provider-neutral abstraction every payment gateway implementation
 * satisfies. Implementations are Spring singletons; they hold no
 * per-transaction state and receive the target gateway row + decoded
 * credentials on every call.
 *
 * <p>This is the only surface the rest of the payment subsystem
 * (routing, order service, webhook dispatcher, refund workflow)
 * talks to. Provider-specific SDK types never escape this package.
 */
public interface PaymentGatewayStrategy {

    /**
     * Which provider this implementation backs. One Strategy bean
     * per {@link GatewayProvider} value.
     */
    GatewayProvider provider();

    /**
     * Create a hosted-checkout session against the gateway. The
     * returned {@link CheckoutResult#checkoutUrl()} is what the
     * customer's browser is redirected to.
     *
     * @param creds  decoded credentials (secret keys, webhook secrets).
     *               Never persist or log these.
     * @param req    normalised checkout request — amount, currency,
     *               customer email, success/cancel URLs, and the
     *               {@code order_token} carried as the gateway's
     *               client-reference field for later webhook match.
     */
    CheckoutResult createCheckout(GatewayCredentials creds, CheckoutRequest req);

    /**
     * Verify that {@code rawPayload} was signed by the gateway using
     * the webhook secret from {@code creds}. Must be constant-time
     * on the signature compare.
     */
    boolean verifySignature(GatewayCredentials creds, String rawPayload, String signatureHeader);

    /**
     * Parse a verified webhook payload into a normalised event. The
     * returned {@link NormalisedEvent#type()} is what the dispatcher
     * branches on; {@link NormalisedEvent#orderToken()} is what it
     * uses to find the matching {@code pending_orders} row.
     *
     * <p>Implementations must be idempotent: the same payload parsed
     * twice returns equal events. The dedup happens at the DB layer
     * via {@code billing_transactions.gateway_transaction_id}.
     */
    NormalisedEvent parseEvent(String rawPayload);

    /**
     * Issue a refund for {@code gatewayTransactionId}. Optional —
     * implementations that do not support programmatic refunds
     * throw {@link UnsupportedOperationException}; the operator then
     * refunds manually in the provider dashboard.
     *
     * @param amountCents  null = full refund
     */
    default void refund(GatewayCredentials creds,
                        String gatewayTransactionId,
                        Long amountCents) {
        throw new UnsupportedOperationException(
                provider() + " does not support programmatic refunds");
    }

    // ---- DTOs ---------------------------------------------------

    record CheckoutRequest(
            String  orderToken,
            String  tier,
            String  organisation,
            String  customerEmail,
            long    amountCents,
            String  currency,
            String  billingCycle,
            String  successUrl,
            String  cancelUrl,
            Map<String, String> metadata) {}

    record CheckoutResult(
            String  checkoutUrl,
            String  gatewaySessionId,
            String  gatewayCustomerId) {}

    record NormalisedEvent(
            EventType type,
            String    orderToken,
            String    gatewayTransactionId,
            String    gatewaySessionId,
            String    gatewayCustomerId,
            String    gatewaySubscriptionId,
            Long      amountCents,
            String    currency,
            String    cardCountry,
            String    bin,
            String    failureReason,
            Map<String, String> raw) {}

    /**
     * The minimal set of event kinds the router reacts to. Every
     * other provider-specific event type collapses into one of these
     * or is ignored.
     */
    enum EventType {
        CHECKOUT_COMPLETED,
        PAYMENT_SUCCEEDED,
        PAYMENT_FAILED,
        PAYMENT_REFUNDED,
        CHECKOUT_CANCELLED,
        SUBSCRIPTION_RENEWED,
        SUBSCRIPTION_CANCELLED,
        IGNORED
    }
}
