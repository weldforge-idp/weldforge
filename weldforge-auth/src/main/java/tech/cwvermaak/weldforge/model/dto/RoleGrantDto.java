package tech.cwvermaak.weldforge.model.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

/**
 * A user's tenant roles under one service account's grant prefix.
 *
 * <p>Deliberately not the whole role set. The caller is scoped to a prefix, so
 * it is told about that prefix and nothing else -- a user holding
 * {@code clepsydra:member}, {@code staff} and {@code leap:admin} reads back as
 * {@code ["clepsydra:member"]} and is not informed the other two exist.
 *
 * <p>See {@code docs/product/scoped-role-grants.md}.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class RoleGrantDto {

    private Long userId;

    /** Echoed back so a caller can see which namespace it is looking at. */
    private String prefix;

    /** The user's roles under the prefix, ordered by name. */
    @Builder.Default
    private List<String> roles = List.of();

    /**
     * Roles this call had to create, named so creation is never silent.
     *
     * <p>Empty on a read, and empty on a write that only used roles which
     * already existed. A caller that expected to create nothing can assert on
     * it -- which is the answer to "create-on-use lets a caller bug litter the
     * tenant", and a better one than a flag the caller would always set.
     */
    @Builder.Default
    private List<String> created = List.of();
}
