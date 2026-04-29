package tech.cwvermaak.intellisso.model.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import tech.cwvermaak.intellisso.model.CrmProviderType;

import java.util.List;
import java.util.Map;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CrmProviderDto {
    private Long id;
    private Long tenantId;
    private String name;
    private CrmProviderType providerType;
    private String baseUrl;
    /** Write-only — never echoed on read. */
    private String apiToken;
    private List<Map<String, Object>> fieldMappings;
    private List<String> matchKeys;
    private Boolean enabled;
    private Boolean dedupeEnabled;
}
