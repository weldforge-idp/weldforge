package tech.cwvermaak.intellisso.model.dto.payment;

import jakarta.validation.constraints.*;
import lombok.Data;

@Data
public class CreateOrderRequest {

    @NotBlank
    @Size(max = 32)
    private String tier;

    @NotBlank
    @Size(max = 255)
    private String organisation;

    @NotBlank
    @Size(max = 255)
    private String contactName;

    @NotBlank
    @Email
    @Size(max = 320)
    private String contactEmail;

    @NotBlank
    @Pattern(regexp = "^[a-z0-9][a-z0-9-]{0,62}[a-z0-9]$",
             message = "lowercase letters, digits and hyphens only; 2–64 chars")
    private String tenantSlug;

    @Size(max = 32)
    private String region;

    @Pattern(regexp = "MONTHLY|ANNUAL")
    private String billingCycle;

    @NotBlank
    @Size(min = 3, max = 3)
    private String currency;

    @NotBlank
    @Size(min = 2, max = 2)
    private String billingCountry;

    @AssertTrue(message = "terms of service must be accepted")
    private boolean termsAccepted;
}
