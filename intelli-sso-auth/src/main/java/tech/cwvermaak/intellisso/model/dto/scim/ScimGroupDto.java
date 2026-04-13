package tech.cwvermaak.intellisso.model.dto.scim;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.*;

import java.util.List;

/** RFC 7643 §4.2 — SCIM Core Group. */
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ScimGroupDto {

    public static final String SCHEMA_GROUP = "urn:ietf:params:scim:schemas:core:2.0:Group";

    @Builder.Default
    private List<String> schemas = List.of(SCHEMA_GROUP);

    private String id;

    private String externalId;

    /** SCIM uses "displayName" for the canonical group label. */
    private String displayName;

    private List<ScimGroupMemberDto> members;

    private ScimMetaDto meta;
}
