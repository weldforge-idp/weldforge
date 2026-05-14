package tech.cwvermaak.weldforge.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import tech.cwvermaak.weldforge.model.dto.GroupRoleMappingDto;
import tech.cwvermaak.weldforge.service.GroupRoleMappingService;

import java.util.List;

/**
 * Admin CRUD for group-to-role mappings, nested under the owning tenant
 * ({@code /api/admin/tenants/{tenantId}/group-role-mappings}). Mappings
 * are immutable — delete and re-create to change priority. Tenant
 * isolation is enforced inside the service via
 * {@code TenantAccessor.requireSameTenant(tenantId)}; SUPER_ADMIN is
 * the only role that may target a foreign tenant.
 */
@RestController
@RequestMapping("/api/admin/tenants/{tenantId}/group-role-mappings")
@RequiredArgsConstructor
public class GroupRoleMappingController {

    private final GroupRoleMappingService mappingService;

    @GetMapping
    public ResponseEntity<List<GroupRoleMappingDto>> list(@PathVariable Long tenantId) {
        return ResponseEntity.ok(mappingService.list(tenantId));
    }

    @PostMapping
    public ResponseEntity<GroupRoleMappingDto> create(@PathVariable Long tenantId,
                                                      @RequestBody GroupRoleMappingDto dto) {
        return ResponseEntity.ok(mappingService.create(tenantId, dto));
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> delete(@PathVariable Long tenantId, @PathVariable Long id) {
        mappingService.delete(tenantId, id);
        return ResponseEntity.noContent().build();
    }
}
