package tech.cwvermaak.intellisso.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import tech.cwvermaak.intellisso.model.dto.*;
import tech.cwvermaak.intellisso.service.AdminService;

import java.util.List;

/**
 * All endpoints below are scoped to the caller's tenant via
 * {@code AdminService} → {@code TenantAccessor}. Cross-tenant reads or writes
 * through this controller are impossible by construction.
 */
@RestController
@RequestMapping("/api/admin")
@RequiredArgsConstructor
public class AdminController {

    private final AdminService adminService;

    // Roles ------------------------------------------------------------
    @GetMapping("/roles")
    public ResponseEntity<List<RoleDto>> listRoles() {
        return ResponseEntity.ok(adminService.listRoles());
    }

    @PostMapping("/roles")
    public ResponseEntity<RoleDto> createRole(@RequestBody RoleDto dto) {
        return ResponseEntity.ok(adminService.createRole(dto));
    }

    @PutMapping("/roles/{id}")
    public ResponseEntity<RoleDto> updateRole(@PathVariable Long id, @RequestBody RoleDto dto) {
        return ResponseEntity.ok(adminService.updateRole(id, dto));
    }

    @DeleteMapping("/roles/{id}")
    public ResponseEntity<Void> deleteRole(@PathVariable Long id) {
        adminService.deleteRole(id);
        return ResponseEntity.noContent().build();
    }

    // Users ------------------------------------------------------------
    @GetMapping("/users")
    public ResponseEntity<List<UserResponseDto>> listUsers() {
        return ResponseEntity.ok(adminService.listUsers());
    }

    @GetMapping("/users/{id}")
    public ResponseEntity<UserResponseDto> getUser(@PathVariable Long id) {
        return ResponseEntity.ok(adminService.getUser(id));
    }

    @DeleteMapping("/users/{id}")
    public ResponseEntity<Void> deleteUser(@PathVariable Long id) {
        adminService.deleteUser(id);
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/users/{id}/reset-mfa")
    public ResponseEntity<java.util.Map<String, Object>> resetUserMfa(@PathVariable Long id) {
        int removed = adminService.resetUserMfa(id);
        return ResponseEntity.ok(java.util.Map.of("removed", removed));
    }

    /**
     * PRD ADM-02: assign an admin console role to a user. Super-admin only.
     * Body: {"adminRole": "NONE|READ_ONLY|TENANT_ADMIN|SUPER_ADMIN"}
     */
    @PostMapping("/users/{id}/admin-role")
    public ResponseEntity<UserResponseDto> setAdminRole(@PathVariable Long id,
                                                         @RequestBody java.util.Map<String, String> body) {
        String raw = body != null ? body.get("adminRole") : null;
        if (raw == null || raw.isBlank()) {
            throw new IllegalArgumentException("adminRole is required");
        }
        tech.cwvermaak.intellisso.model.AdminRole role;
        try {
            role = tech.cwvermaak.intellisso.model.AdminRole.valueOf(raw);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException(
                    "Invalid adminRole — expected NONE, READ_ONLY, TENANT_ADMIN, or SUPER_ADMIN");
        }
        return ResponseEntity.ok(adminService.setAdminRole(id, role));
    }

    // Environments -----------------------------------------------------
    @GetMapping("/environments")
    public ResponseEntity<List<EnvironmentDto>> listEnvironments() {
        return ResponseEntity.ok(adminService.listEnvironments());
    }

    @PostMapping("/environments")
    public ResponseEntity<EnvironmentDto> createEnvironment(@RequestBody EnvironmentDto dto) {
        return ResponseEntity.ok(adminService.createEnvironment(dto));
    }

    @PutMapping("/environments/{id}")
    public ResponseEntity<EnvironmentDto> updateEnvironment(@PathVariable Long id, @RequestBody EnvironmentDto dto) {
        return ResponseEntity.ok(adminService.updateEnvironment(id, dto));
    }

    @DeleteMapping("/environments/{id}")
    public ResponseEntity<Void> deleteEnvironment(@PathVariable Long id) {
        adminService.deleteEnvironment(id);
        return ResponseEntity.noContent().build();
    }

    // App clients ------------------------------------------------------
    @GetMapping("/app-clients")
    public ResponseEntity<List<AppClientDto>> listAppClients() {
        return ResponseEntity.ok(adminService.listAppClients());
    }

    @PostMapping("/app-clients")
    public ResponseEntity<AppClientDto> createAppClient(@RequestBody AppClientDto dto) {
        return ResponseEntity.ok(adminService.createAppClient(dto));
    }

    @PutMapping("/app-clients/{id}")
    public ResponseEntity<AppClientDto> updateAppClient(@PathVariable Long id, @RequestBody AppClientDto dto) {
        return ResponseEntity.ok(adminService.updateAppClient(id, dto));
    }

    @DeleteMapping("/app-clients/{id}")
    public ResponseEntity<Void> deleteAppClient(@PathVariable Long id) {
        adminService.deleteAppClient(id);
        return ResponseEntity.noContent().build();
    }

    /** Rotate an app client's secret. PRD TOK-01 — new key returned once. */
    @PostMapping("/app-clients/{id}/rotate")
    public ResponseEntity<AppClientDto> rotateAppClient(@PathVariable Long id) {
        return ResponseEntity.ok(adminService.rotateAppClient(id));
    }
}
