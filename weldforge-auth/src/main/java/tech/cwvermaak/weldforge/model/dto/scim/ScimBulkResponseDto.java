package tech.cwvermaak.weldforge.model.dto.scim;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.*;

import java.util.List;

/** RFC 7644 section 3.7 — SCIM BulkResponse envelope. */
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ScimBulkResponseDto {

    public static final String SCHEMA_BULK_RESPONSE = "urn:ietf:params:scim:api:messages:2.0:BulkResponse";

    @Builder.Default
    private List<String> schemas = List.of(SCHEMA_BULK_RESPONSE);

    @JsonProperty("Operations")
    private List<BulkOperationResponse> operations;

    @Getter
    @Setter
    @NoArgsConstructor
    @AllArgsConstructor
    @Builder
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static class BulkOperationResponse {
        private String method;
        private String bulkId;
        private String status;
        private Object response;
        private String location;
    }
}
