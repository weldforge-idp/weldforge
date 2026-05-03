package tech.cwvermaak.weldforge.model.dto.payment;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class CreateOrderResponse {
    private String orderToken;
    private String checkoutUrl;
    private String gatewayProvider;
    private long amountCents;
    private String currency;
    private long slugReservationExpiresInSeconds;
}
