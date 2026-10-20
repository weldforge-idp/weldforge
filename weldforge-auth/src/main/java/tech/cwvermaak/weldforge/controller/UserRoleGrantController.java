package tech.cwvermaak.weldforge.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import tech.cwvermaak.weldforge.model.dto.RoleGrantDto;
import tech.cwvermaak.weldforge.service.RoleGrantService;

import java.util.List;
import java.util.Map;

/**
 * Role assignment for a credential scoped to one name prefix.
 *
 * <p>The two endpoints a service account with a {@code roleGrantPrefix} may
 * reach, and the only ones. A downstream application manages its own namespace
 * of roles here instead of being handed {@code TENANT_ADMIN}, which would also
 * let it delete users, reset MFA and edit OIDC clients for the whole tenant.
 *
 * <p>Separate from {@code PUT /api/admin/users/{id}/roles} on purpose. That one
 * is for human admins, takes role <em>ids</em>, and replaces the whole set.
 * This one is for a machine, takes <em>names</em> because the caller knows the
 * names it owns and not the ids, and replaces only its own namespace. The two
 * do not share a path because they do not share a caller, a shape, or a blast
 * radius.
 *
 * <p>The guard is in {@link RoleGrantService}, not here and not in a filter:
 * {@code AppAuthorizationFilter} lets {@code /api/admin/**} through when no
 * {@code x-app-authorization} header is present so the SPA can use a bearer
 * token, which means an endpoint under this prefix is not protected merely by
 * living here.
 *
 * <p>Contract, statuses and the reasoning:
 * {@code docs/product/scoped-role-grants.md}.
 */
@RestController
@RequestMapping("/api/admin/users/{id}/role-grants")
@RequiredArgsConstructor
public class UserRoleGrantController {

    private final RoleGrantService roleGrantService;

    /** The user's roles under the caller's prefix. Not audited: it is a read. */
    @GetMapping
    public ResponseEntity<RoleGrantDto> list(@PathVariable Long id) {
        return ResponseEntity.ok(roleGrantService.list(id));
    }

    /**
     * Replace the user's roles under the caller's prefix, leaving every other
     * role untouched.
     *
     * <p>Body: {@code {"roles": ["clepsydra:member", "clepsydra:pm"]}}, or
     * {@code {"roles": []}} to remove the user's roles in that namespace and
     * nothing else.
     *
     * <p>A name outside the prefix refuses the whole call with 400 and writes
     * nothing. 400 rather than 403 because it is a payload the caller can fix,
     * where 403 means the credential may not do this at all and needs a human.
     */
    @PutMapping
    public ResponseEntity<RoleGrantDto> replace(@PathVariable Long id,
                                                @RequestBody(required = false) Map<String, Object> body) {
        Object raw = body == null ? null : body.get("roles");
        if (raw != null && !(raw instanceof List)) {
            throw new IllegalArgumentException("roles must be an array of role names");
        }
        List<String> names = new java.util.ArrayList<>();
        if (raw instanceof List<?> list) {
            for (Object o : list) {
                if (o == null) continue;
                if (!(o instanceof String s)) {
                    throw new IllegalArgumentException("roles must contain role names as strings");
                }
                names.add(s);
            }
        }
        return ResponseEntity.ok(roleGrantService.replace(id, names));
    }
}
