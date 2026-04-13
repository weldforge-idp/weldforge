package tech.cwvermaak.intellisso.model.dto.scim;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.*;

import java.util.List;

/** RFC 7644 §3.5.2 — PATCH operation envelope. */
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ScimPatchRequestDto {

    public static final String SCHEMA_PATCH = "urn:ietf:params:scim:api:messages:2.0:PatchOp";

    @Builder.Default
    private List<String> schemas = List.of(SCHEMA_PATCH);

    @com.fasterxml.jackson.annotation.JsonProperty("Operations")
    private List<Operation> operations;

    @Getter
    @Setter
    @NoArgsConstructor
    @AllArgsConstructor
    @Builder
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static class Operation {
        /** add | remove | replace */
        private String op;
        private String path;
        /**
         * Polymorphic; can be a primitive ({@code true}/{@code false}/string)
         * or a complex object. Jackson hands it back as Object — service
         * code coerces.
         */
        private Object value;
    }
}
