package tech.cwvermaak.weldforge.model.payment;

/**
 * Identifies the payment provider backing a {@code payment_gateways}
 * row. One enum value per Strategy implementation.
 *
 * <p>Adding a new provider requires:
 * <ol>
 *   <li>A new enum value here.</li>
 *   <li>A new {@code PaymentGatewayStrategy} bean whose
 *       {@link tech.cwvermaak.weldforge.service.payment.gateway.PaymentGatewayStrategy#provider()}
 *       returns the value.</li>
 *   <li>Fee-structure defaults registered in {@code FeeCalculator}.</li>
 *   <li>A webhook path entry in {@code WebhookController}.</li>
 * </ol>
 */
public enum GatewayProvider {
    STRIPE,
    PADDLE,
    PAYFAST,
    YOCO,
    PEACH
}
