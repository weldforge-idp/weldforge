package tech.cwvermaak.weldforge.model.dto.payment;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class CreateOrderResponse {

    /**
     * What the caller should do next. Present so a client never has to infer
     * intent from a null {@code checkoutUrl} -- the difference between "pay
     * now" and "we will email you" is a product decision, not a null check.
     */
    public enum NextStep {
        /** {@code checkoutUrl} is set; redirect the browser to it. */
        CHECKOUT,
        /**
         * The order is recorded and a human will follow up. No gateway is
         * configured for this currency/country, so there is nothing to pay
         * against yet. {@code checkoutUrl} is null.
         */
        MANUAL_FOLLOW_UP
    }

    private String orderToken;
    private String checkoutUrl;
    private NextStep nextStep;
    private String gatewayProvider;
    private long amountCents;
    private String currency;
    private long slugReservationExpiresInSeconds;
}
