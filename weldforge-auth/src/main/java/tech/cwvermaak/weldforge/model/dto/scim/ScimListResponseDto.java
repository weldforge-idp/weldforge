package tech.cwvermaak.weldforge.model.dto.scim;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.*;

import java.util.List;

/** RFC 7644 §3.4.2 — SCIM List Response envelope. */
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ScimListResponseDto<T> {

    public static final String SCHEMA_LIST = "urn:ietf:params:scim:api:messages:2.0:ListResponse";

    @Builder.Default
    private List<String> schemas = List.of(SCHEMA_LIST);

    private long totalResults;
    private long itemsPerPage;
    private long startIndex;

    /** Spec name is "Resources" with a capital R. */
    @com.fasterxml.jackson.annotation.JsonProperty("Resources")
    private List<T> resources;
}
