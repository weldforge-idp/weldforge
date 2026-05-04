package tech.cwvermaak.weldforge.model.dto;

import lombok.*;
import tech.cwvermaak.weldforge.model.TenantMfaPolicy;

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
