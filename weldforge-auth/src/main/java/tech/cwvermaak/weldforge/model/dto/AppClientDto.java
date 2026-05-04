package tech.cwvermaak.weldforge.model.dto;

import lombok.*;

import java.util.List;
import java.util.Map;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class AppClientDto {
    private Long id;
    private String clientName;
    /** Returned only on create/rotate so the caller can capture it once. */
    private String apiKey;
    /** Non-secret display prefix. Safe to list in the admin UI. */
    private String apiKeyPrefix;
    /** Optional {path, methods} allow-list. PRD TOK-02. */
    private List<Map<String, Object>> scopes;
    private Boolean enabled;
}
