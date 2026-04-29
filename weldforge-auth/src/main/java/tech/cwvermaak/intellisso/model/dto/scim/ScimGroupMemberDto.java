package tech.cwvermaak.intellisso.model.dto.scim;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.*;

/**
 * RFC 7643 §4.2 — Group member entry. {@code value} is the user id;
 * {@code $ref} is the absolute URL to the User resource so SCIM clients
 * can dereference it without rebuilding the URL themselves.
 */
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ScimGroupMemberDto {

    private String value;

    /** Display name; SCIM spec calls it "display". */
    private String display;

    /** Always "User" for now — group nesting is not supported yet. */
    private String type;

    @JsonProperty("$ref")
    private String ref;
}
