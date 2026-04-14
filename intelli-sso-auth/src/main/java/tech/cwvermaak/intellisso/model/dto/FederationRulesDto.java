package tech.cwvermaak.intellisso.model.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;
import java.util.Map;

/**
 * Wire format for a tenant's federation configuration (PRD FED-02, FED-04).
 * Lists are kept as raw maps because the rule schemas are intentionally
 * open-ended — adding a new matching strategy or transform option should
 * not require a wire-format change.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class FederationRulesDto {
    private List<Map<String, Object>> matchingRules;
    private List<Map<String, Object>> claimTransforms;
}
