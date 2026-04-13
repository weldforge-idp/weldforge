package tech.cwvermaak.intellisso.model.dto;

import lombok.*;
import tech.cwvermaak.intellisso.model.TenantMfaPolicy;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class MfaPolicyDto {

    private Long id;
    private Long tenantId;
    private TenantMfaPolicy.Enforcement enforcement;
    private Integer gracePeriodDays;
    private Integer defaultStepupMaxAge;
}
