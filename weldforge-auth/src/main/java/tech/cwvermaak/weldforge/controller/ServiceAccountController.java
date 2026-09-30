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

    /**
     * Issue a new secret. The body is optional and may carry
     * {@code expiresInDays} / {@code expiresInHours} to set a new lifetime;
     * omit it to keep the existing one. Rotating an already-expired token
     * without a new lifetime is refused rather than returning a token that
     * cannot authenticate.
     */
    @PostMapping("/{id}/rotate")
    public ResponseEntity<ServiceAccountDto> rotate(
            @PathVariable Long id,
            @RequestBody(required = false) ServiceAccountDto request) {
        return ResponseEntity.ok(service.rotate(id, request));
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> delete(@PathVariable Long id) {
        service.delete(id);
        return ResponseEntity.noContent().build();
    }
}
