package tech.cwvermaak.weldforge.model.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * A registered scope and the words shown for it on the consent screen.
 *
 * <p>{@code descriptions} is keyed by language tag — {@code {"en": "...",
 * "de": "..."}}. A scope with an empty map is registered but unexplained,
 * which renders exactly as an unregistered scope does.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class OidcScopeDto {

    private Long id;
    private String name;

    @Builder.Default
    private Map<String, String> descriptions = new LinkedHashMap<>();

    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;
}
