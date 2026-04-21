package tech.cwvermaak.intellisso.model.dto.payment;

import lombok.Builder;
import lombok.Data;
import tech.cwvermaak.intellisso.model.payment.GatewayProvider;
import tech.cwvermaak.intellisso.model.payment.GatewayScope;

import java.util.List;
import java.util.Map;

@Data
@Builder
public class PaymentGatewayDto {
    private Long id;
    private GatewayScope scope;
    private Long tenantId;
    private GatewayProvider provider;
    private String displayName;
    private boolean enabled;
    private int priority;
    private List<String> supportedCurrencies;
    private List<String> supportedCountries;
    private Map<String, Object> config;
    /** Plaintext credentials (write-only). Never populated on reads. */
    private Map<String, String> credentials;
    private Map<String, Object> feeStructure;
}
