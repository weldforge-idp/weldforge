package tech.cwvermaak.intellisso.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import tech.cwvermaak.intellisso.model.Role;
import tech.cwvermaak.intellisso.model.dto.RoleDto;
import tech.cwvermaak.intellisso.service.AdminService;

import java.util.List;

@RestController
@RequestMapping("/api/admin")
@RequiredArgsConstructor
public class AdminController {

    private final AdminService adminService;

    @PostMapping("/roles")
    public ResponseEntity<Role> createRole(@RequestBody RoleDto dto) {
        Role created = adminService.createRole(dto);
        return ResponseEntity.ok(created);
    }

    @GetMapping("/roles")
    public ResponseEntity<List<Role>> getAllRoles() {
        return ResponseEntity.ok(adminService.getAllRoles());
    }

    // Add PUT /roles/{id}, DELETE /roles/{id}, and similar for Environment / Responsibility
}