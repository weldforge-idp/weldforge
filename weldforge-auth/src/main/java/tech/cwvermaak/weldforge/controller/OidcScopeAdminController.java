package tech.cwvermaak.weldforge.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import tech.cwvermaak.weldforge.model.dto.OidcScopeDto;
import tech.cwvermaak.weldforge.service.oidc.OidcScopeService;

import java.util.List;

/**
 * Admin CRUD for a tenant's OIDC scope registry — the words the consent
 * screen shows for each scope, and the names discovery advertises.
 *
 * <p>The scope name travels in the body or the query string, never as a path
 * segment. An RFC 6749 scope token may contain a slash ({@code read/write} is
 * legal), which a path variable would split; there is no version of this that
 * is both RESTful and correct for every name a tenant may legitimately
 * register.
 *
 * <p>Nothing here grants anything. A client may still only ask for the scopes
 * registered against that client; this registry decides what a person is
 * <em>told</em> those scopes mean.
 */
@RestController
@RequestMapping("/api/admin/oidc/scopes")
@RequiredArgsConstructor
public class OidcScopeAdminController {

    private final OidcScopeService scopeService;

    @GetMapping
    public ResponseEntity<List<OidcScopeDto>> list() {
        return ResponseEntity.ok(scopeService.list());
    }

    /** Register a scope, or replace the words registered for it. */
    @PostMapping
    public ResponseEntity<OidcScopeDto> upsert(@RequestBody OidcScopeDto dto) {
        return ResponseEntity.ok(scopeService.upsert(dto.getName(), dto.getDescriptions()));
    }

    /**
     * Replace the whole registry with exactly this list.
     *
     * <p>For a screen that edits the entire list at once. Editing one scope
     * goes through {@link #upsert} instead, which does not silently drop a
     * scope another admin added while the screen was open.
     */
    @PutMapping
    public ResponseEntity<List<OidcScopeDto>> replaceAll(@RequestBody List<OidcScopeDto> scopes) {
        return ResponseEntity.ok(scopeService.replaceAll(scopes));
    }

    @DeleteMapping
    public ResponseEntity<Void> delete(@RequestParam String name) {
        scopeService.delete(name);
        return ResponseEntity.noContent().build();
    }
}
