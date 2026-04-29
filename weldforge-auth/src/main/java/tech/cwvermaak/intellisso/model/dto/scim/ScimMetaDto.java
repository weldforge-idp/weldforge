package tech.cwvermaak.intellisso.model.dto.scim;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.*;

import java.time.LocalDateTime;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ScimMetaDto {
    private String resourceType;
    private LocalDateTime created;
    private LocalDateTime lastModified;
    /** Absolute URL to the resource — clients use this for follow-up calls. */
    private String location;
}
