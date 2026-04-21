package tech.cwvermaak.intellisso.service.payment.gateway;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.stripe.Stripe;
import com.stripe.exception.SignatureVerificationException;
import com.stripe.exception.StripeException;
import com.stripe.model.Event;
import com.stripe.model.checkout.Session;
import com.stripe.net.Webhook;
import com.stripe.param.checkout.SessionCreateParams;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import tech.cwvermaak.intellisso.model.payment.GatewayProvider;

import java.util.HashMap;
import java.util.Map;

/**
 * Stripe Checkout Session implementation of {@link PaymentGatewayStrategy}.
 *
 * <p>Strategy lifecycle:
 * <ol>
 *   <li>{@link #createCheckout} creates a Stripe {@code checkout.Session}
 *       with the order token stored as {@code client_reference_id}.</li>
 *   <li>Stripe hosts the payment page; on completion it delivers a
 *       {@code checkout.session.completed} webhook.</li>
 *   <li>{@link #parseEvent} reads the session, pulls
 *       {@code client_reference_id} back out, and emits a normalised
 *       {@link NormalisedEvent} the rest of the subsystem handles.</li>
 * </ol>
 *
 * <p>Credentials required:
 * <pre>{
 *   "secret_key":    "sk_live_... or sk_test_...",
 *   "webhook_secret":"whsec_..."
 * }</pre>
 */
@Component
@Slf4j
public class StripeGateway implements PaymentGatewayStrategy {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Override
    public GatewayProvider provider() {
        return GatewayProvider.STRIPE;
    }

    @Override
    public CheckoutResult createCheckout(GatewayCredentials creds, CheckoutRequest req) {
        Stripe.apiKey = creds.require("secret_key");

        SessionCreateParams.LineItem.PriceData priceData = SessionCreateParams.LineItem.PriceData.builder()
                .setCurrency(req.currency().toLowerCase())
                .setUnitAmount(req.amountCents())
                .setProductData(SessionCreateParams.LineItem.PriceData.ProductData.builder()
                        .setName("WeldForge " + humaniseTier(req.tier()))
                        .setDescription("Organisation: " + req.organisation())
                        .build())
                .build();

        SessionCreateParams params = SessionCreateParams.builder()
                .setMode(SessionCreateParams.Mode.PAYMENT)
                .setClientReferenceId(req.orderToken())
                .setCustomerEmail(req.customerEmail())
                .setSuccessUrl(req.successUrl())
                .setCancelUrl(req.cancelUrl())
                .addLineItem(SessionCreateParams.LineItem.builder()
                        .setQuantity(1L)
                        .setPriceData(priceData)
                        .build())
                .putAllMetadata(req.metadata() == null ? Map.of() : req.metadata())
                .build();

        try {
            Session session = Session.create(params);
            return new CheckoutResult(session.getUrl(), session.getId(), session.getCustomer());
        } catch (StripeException e) {
            log.error("Stripe checkout.Session create failed: {}", e.getMessage(), e);
            throw new IllegalStateException("Stripe checkout failed: " + e.getMessage(), e);
        }
    }

    @Override
    public boolean verifySignature(GatewayCredentials creds, String rawPayload, String signatureHeader) {
        if (signatureHeader == null || signatureHeader.isBlank()) return false;
        String webhookSecret = creds.require("webhook_secret");
        try {
            Webhook.constructEvent(rawPayload, signatureHeader, webhookSecret);
            return true;
        } catch (SignatureVerificationException e) {
            return false;
        } catch (Exception e) {
            log.debug("Stripe signature check failed: {}", e.toString());
            return false;
        }
    }

    @Override
    public NormalisedEvent parseEvent(String rawPayload) {
        try {
            JsonNode root = MAPPER.readTree(rawPayload);
            String type = root.path("type").asText();
            JsonNode obj = root.path("data").path("object");

            return switch (type) {
                case "checkout.session.completed", "checkout.session.async_payment_succeeded" ->
                        new NormalisedEvent(
                                EventType.CHECKOUT_COMPLETED,
                                textOrNull(obj, "client_reference_id"),
                                textOrNull(obj, "payment_intent"),
                                textOrNull(obj, "id"),
                                textOrNull(obj, "customer"),
                                textOrNull(obj, "subscription"),
                                obj.path("amount_total").isNumber() ? obj.path("amount_total").asLong() : null,
                                upper(textOrNull(obj, "currency")),
                                null, null, null,
                                flatten(root));
                case "checkout.session.expired", "checkout.session.async_payment_failed" ->
                        new NormalisedEvent(
                                EventType.CHECKOUT_CANCELLED,
                                textOrNull(obj, "client_reference_id"),
                                textOrNull(obj, "payment_intent"),
                                textOrNull(obj, "id"),
                                textOrNull(obj, "customer"),
                                null, null, null, null, null, null,
                                flatten(root));
                case "payment_intent.succeeded" ->
                        new NormalisedEvent(
                                EventType.PAYMENT_SUCCEEDED,
                                orderTokenFromMetadata(obj),
                                textOrNull(obj, "id"),
                                null,
                                textOrNull(obj, "customer"),
                                null,
                                obj.path("amount_received").isNumber() ? obj.path("amount_received").asLong() : null,
                                upper(textOrNull(obj, "currency")),
                                null, null, null,
                                flatten(root));
                case "payment_intent.payment_failed" ->
                        new NormalisedEvent(
                                EventType.PAYMENT_FAILED,
                                orderTokenFromMetadata(obj),
                                textOrNull(obj, "id"),
                                null, null, null, null, null, null, null,
                                obj.path("last_payment_error").path("message").asText(null),
                                flatten(root));
                case "charge.refunded" ->
                        new NormalisedEvent(
                                EventType.PAYMENT_REFUNDED,
                                orderTokenFromMetadata(obj),
                                textOrNull(obj, "payment_intent"),
                                null, textOrNull(obj, "customer"), null,
                                obj.path("amount_refunded").isNumber() ? obj.path("amount_refunded").asLong() : null,
                                upper(textOrNull(obj, "currency")),
                                null, null, null, flatten(root));
                default ->
                        new NormalisedEvent(EventType.IGNORED, null, null, null, null, null, null, null,
                                null, null, null, Map.of("stripe_type", type));
            };
        } catch (Exception e) {
            throw new IllegalStateException("Failed to parse Stripe event JSON", e);
        }
    }

    @Override
    public void refund(GatewayCredentials creds, String gatewayTransactionId, Long amountCents) {
        Stripe.apiKey = creds.require("secret_key");
        try {
            com.stripe.param.RefundCreateParams.Builder b = com.stripe.param.RefundCreateParams.builder()
                    .setPaymentIntent(gatewayTransactionId);
            if (amountCents != null) b.setAmount(amountCents);
            com.stripe.model.Refund.create(b.build());
        } catch (StripeException e) {
            throw new IllegalStateException("Stripe refund failed: " + e.getMessage(), e);
        }
    }

    private static String humaniseTier(String tier) {
        if (tier == null) return "Subscription";
        String[] parts = tier.split("-");
        StringBuilder sb = new StringBuilder();
        for (String p : parts) {
            if (sb.length() > 0) sb.append(' ');
            sb.append(Character.toUpperCase(p.charAt(0))).append(p.substring(1));
        }
        return sb.toString();
    }

    private static String textOrNull(JsonNode node, String field) {
        JsonNode v = node.path(field);
        return v.isTextual() ? v.asText() : null;
    }

    private static String upper(String v) { return v == null ? null : v.toUpperCase(); }

    private static String orderTokenFromMetadata(JsonNode paymentIntent) {
        JsonNode md = paymentIntent.path("metadata");
        if (md.isObject()) {
            JsonNode t = md.path("orderToken");
            if (t.isTextual()) return t.asText();
        }
        return null;
    }

    private static Map<String, String> flatten(JsonNode event) {
        Map<String, String> out = new HashMap<>();
        out.put("id",   event.path("id").asText(""));
        out.put("type", event.path("type").asText(""));
        return out;
    }
}
