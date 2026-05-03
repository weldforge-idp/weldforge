package tech.cwvermaak.weldforge.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import tech.cwvermaak.weldforge.model.dto.ServiceAccountDto;
import tech.cwvermaak.weldforge.service.ServiceAccountService;

import java.util.List;

/**
 * Admin API for service accounts (PRD TOK-03). Lives under /api/admin
 * so it is gated by the authenticated admin chain and the same tenant
 * isolation rules as the rest of the admin surface.
 */
@RestController
@RequestMapping("/api/admin/service-accounts")
@RequiredArgsConstructor
public class ServiceAccountController {

    private final ServiceAccountService service;

    @GetMapping
    public ResponseEntity<List<ServiceAccountDto>> list() {
        return ResponseEntity.ok(service.list());
    }

    @PostMapping
    public ResponseEntity<ServiceAccountDto> create(@RequestBody ServiceAccountDto dto) {
        return ResponseEntity.ok(service.create(dto));
    }

    @PutMapping("/{id}")
    public ResponseEntity<ServiceAccountDto> update(@PathVariable Long id, @RequestBody ServiceAccountDto dto) {
        return ResponseEntity.ok(service.update(id, dto));
    }

    @PostMapping("/{id}/rotate")
    public ResponseEntity<ServiceAccountDto> rotate(@PathVariable Long id) {
        return ResponseEntity.ok(service.rotate(id));
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> delete(@PathVariable Long id) {
        service.delete(id);
        return ResponseEntity.noContent().build();
    }
}
