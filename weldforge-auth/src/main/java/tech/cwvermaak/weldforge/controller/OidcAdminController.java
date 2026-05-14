package tech.cwvermaak.weldforge.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import tech.cwvermaak.weldforge.model.dto.OidcClientDto;
import tech.cwvermaak.weldforge.service.oidc.OidcClientService;

import java.util.List;

/**
 * Admin CRUD for tenant OIDC clients. The URL nests the resource under
 * its owning tenant ({@code /api/admin/tenants/{tenantId}/oidc/clients})
 * so SUPER_ADMIN can target a foreign tenant explicitly. Tenant isolation
 * for non-super admins is enforced inside {@link OidcClientService} via
 * {@code TenantAccessor.requireSameTenant(tenantId)}.
 */
@RestController
@RequestMapping("/api/admin/tenants/{tenantId}/oidc/clients")
@RequiredArgsConstructor
public class OidcAdminController {

    private final OidcClientService oidcClientService;

    @GetMapping
    public ResponseEntity<List<OidcClientDto>> list(@PathVariable Long tenantId) {
        return ResponseEntity.ok(oidcClientService.list(tenantId));
    }

    @PostMapping
    public ResponseEntity<OidcClientDto> create(@PathVariable Long tenantId,
                                                @RequestBody OidcClientDto dto) {
        return ResponseEntity.ok(oidcClientService.create(tenantId, dto));
    }

    @PostMapping("/{id}/rotate-secret")
    public ResponseEntity<OidcClientDto> rotateSecret(@PathVariable Long tenantId,
                                                     @PathVariable Long id) {
        return ResponseEntity.ok(oidcClientService.rotateSecret(tenantId, id));
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> delete(@PathVariable Long tenantId, @PathVariable Long id) {
        oidcClientService.delete(tenantId, id);
        return ResponseEntity.noContent().build();
    }
}
