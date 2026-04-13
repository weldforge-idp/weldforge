package tech.cwvermaak.intellisso.model.dto.scim;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.*;

import java.util.List;

/** RFC 7644 §3.12 — SCIM error response shape. */
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ScimErrorDto {

    public static final String SCHEMA_ERROR = "urn:ietf:params:scim:api:messages:2.0:Error";

    @Builder.Default
    private List<String> schemas = List.of(SCHEMA_ERROR);

    private String status;
    private String scimType;
    private String detail;
}
