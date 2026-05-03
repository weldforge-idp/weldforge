package tech.cwvermaak.weldforge.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import tech.cwvermaak.weldforge.model.dto.OidcClientDto;
import tech.cwvermaak.weldforge.service.oidc.OidcClientService;

import java.util.List;

/**
 * Admin CRUD for tenant OIDC clients. The dynamic registration RFC 7591
 * endpoint can sit alongside this in a future pass — for now, tenant
 * admins manage clients explicitly through the WeldForge UI.
 */
@RestController
@RequestMapping("/api/admin/oidc/clients")
@RequiredArgsConstructor
public class OidcAdminController {

    private final OidcClientService oidcClientService;

    @GetMapping
    public ResponseEntity<List<OidcClientDto>> list() {
        return ResponseEntity.ok(oidcClientService.list());
    }

    @PostMapping
    public ResponseEntity<OidcClientDto> create(@RequestBody OidcClientDto dto) {
        return ResponseEntity.ok(oidcClientService.create(dto));
    }

    @PostMapping("/{id}/rotate-secret")
    public ResponseEntity<OidcClientDto> rotateSecret(@PathVariable Long id) {
        return ResponseEntity.ok(oidcClientService.rotateSecret(id));
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> delete(@PathVariable Long id) {
        oidcClientService.delete(id);
        return ResponseEntity.noContent().build();
    }
}
