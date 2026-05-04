package tech.cwvermaak.weldforge.model.dto.scim;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.*;

import java.util.List;
import java.util.Map;

/** RFC 7644 section 3.7 — SCIM BulkRequest envelope. */
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ScimBulkRequestDto {

    public static final String SCHEMA_BULK_REQUEST = "urn:ietf:params:scim:api:messages:2.0:BulkRequest";

    @Builder.Default
    private List<String> schemas = List.of(SCHEMA_BULK_REQUEST);

    @JsonProperty("Operations")
    private List<BulkOperation> operations;

    @Getter
    @Setter
    @NoArgsConstructor
    @AllArgsConstructor
    @Builder
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static class BulkOperation {
        /** POST, PUT, PATCH, or DELETE */
        private String method;
        private String bulkId;
        /** e.g. /Users, /Users/{id}, /Groups, /Groups/{id} */
        private String path;
        /** Request body for POST/PUT/PATCH — deserialized as a generic map. */
        private Map<String, Object> data;
    }
}
