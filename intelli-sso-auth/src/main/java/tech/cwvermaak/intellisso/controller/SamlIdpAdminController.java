package tech.cwvermaak.intellisso.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import tech.cwvermaak.intellisso.model.dto.SamlServiceProviderDto;
import tech.cwvermaak.intellisso.service.saml.SamlIdpService;

import java.util.List;

/**
 * Admin CRUD for downstream SAML Service Provider registrations.
 * Follows the same pattern as {@link OidcAdminController}.
 */
@RestController
@RequestMapping("/api/admin/saml/service-providers")
@RequiredArgsConstructor
public class SamlIdpAdminController {

    private final SamlIdpService samlIdpService;

    @GetMapping
    public ResponseEntity<List<SamlServiceProviderDto>> list() {
        return ResponseEntity.ok(samlIdpService.list());
    }

    @PostMapping
    public ResponseEntity<SamlServiceProviderDto> create(@RequestBody SamlServiceProviderDto dto) {
        return ResponseEntity.ok(samlIdpService.create(dto));
    }

    @PutMapping("/{id}")
    public ResponseEntity<SamlServiceProviderDto> update(@PathVariable Long id,
                                                          @RequestBody SamlServiceProviderDto dto) {
        return ResponseEntity.ok(samlIdpService.update(id, dto));
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> delete(@PathVariable Long id) {
        samlIdpService.delete(id);
        return ResponseEntity.noContent().build();
    }
}
