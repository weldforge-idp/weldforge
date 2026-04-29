package tech.cwvermaak.intellisso.model.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class WebhookSubscriptionDto {
    private Long id;
    private String name;
    private String targetUrl;
    /** Returned only on create/rotate — the caller must capture it once. */
    private String secret;
    private List<String> eventFilters;
    private Boolean enabled;
    private Integer maxAttempts;
}
