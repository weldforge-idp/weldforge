package tech.cwvermaak.weldforge.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import tech.cwvermaak.weldforge.model.dto.ServiceAccountDto;
import tech.cwvermaak.weldforge.service.ServiceAccountService;

import java.util.List;

/**
 * Admin API for service accounts (PRD TOK-03), nested under the owning
 * tenant ({@code /api/admin/tenants/{tenantId}/service-accounts}). Tenant
 * isolation is enforced inside {@link ServiceAccountService} via
 * {@code TenantAccessor.requireSameTenant(tenantId)}; SUPER_ADMIN may
 * target a foreign tenant.
 */
@RestController
@RequestMapping("/api/admin/tenants/{tenantId}/service-accounts")
@RequiredArgsConstructor
public class ServiceAccountController {

    private final ServiceAccountService service;

    @GetMapping
    public ResponseEntity<List<ServiceAccountDto>> list(@PathVariable Long tenantId) {
        return ResponseEntity.ok(service.list(tenantId));
    }

    @PostMapping
    public ResponseEntity<ServiceAccountDto> create(@PathVariable Long tenantId,
                                                    @RequestBody ServiceAccountDto dto) {
        return ResponseEntity.ok(service.create(tenantId, dto));
    }

    @PutMapping("/{id}")
    public ResponseEntity<ServiceAccountDto> update(@PathVariable Long tenantId,
                                                    @PathVariable Long id,
                                                    @RequestBody ServiceAccountDto dto) {
        return ResponseEntity.ok(service.update(tenantId, id, dto));
    }

    @PostMapping("/{id}/rotate")
    public ResponseEntity<ServiceAccountDto> rotate(@PathVariable Long tenantId,
                                                    @PathVariable Long id) {
        return ResponseEntity.ok(service.rotate(tenantId, id));
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> delete(@PathVariable Long tenantId, @PathVariable Long id) {
        service.delete(tenantId, id);
        return ResponseEntity.noContent().build();
    }
}
