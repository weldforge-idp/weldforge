package tech.cwvermaak.weldforge.model.dto.scim;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.*;

import java.util.List;

/**
 * RFC 7643 §4.1 — SCIM Core User. We surface the subset that real-world
 * provisioners (Okta, Workday, Entra ID) actually populate; everything
 * else is intentionally absent so the JSON stays compact.
 */
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ScimUserDto {

    public static final String SCHEMA_USER = "urn:ietf:params:scim:schemas:core:2.0:User";

    @Builder.Default
    private List<String> schemas = List.of(SCHEMA_USER);

    private String id;

    /** External ID assigned by the upstream provisioner (e.g. Okta's user id). */
    private String externalId;

    private String userName;

    private ScimNameDto name;

    private String displayName;

    private List<ScimEmailDto> emails;

    @Builder.Default
    private boolean active = true;

    private ScimMetaDto meta;
}
