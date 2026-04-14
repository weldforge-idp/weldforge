package tech.cwvermaak.intellisso.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import tech.cwvermaak.intellisso.model.dto.SamlServiceProviderDto;
import tech.cwvermaak.intellisso.service.saml.SamlIdpService;
import tech.cwvermaak.intellisso.service.saml.SamlMetadataParser;

import java.util.List;
import java.util.Map;

/**
 * Admin CRUD for downstream SAML Service Provider registrations.
 * Follows the same pattern as {@link OidcAdminController}.
 */
@RestController
@RequestMapping("/api/admin/saml/service-providers")
@RequiredArgsConstructor
public class SamlIdpAdminController {

    private final SamlIdpService samlIdpService;
    private final SamlMetadataParser metadataParser;

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

    /**
     * PRD SAM-05: parse SAML metadata (either pasted XML or fetched from a
     * URL) and return a populated {@link SamlServiceProviderDto} that the
     * admin portal pre-fills into the create form. This is a read-only
     * parse — nothing is persisted until the admin hits Create.
     */
    @PostMapping("/import-metadata")
    public ResponseEntity<SamlServiceProviderDto> importMetadata(
            @RequestBody Map<String, String> body) {
        String xml = body != null ? body.get("metadataXml") : null;
        String url = body != null ? body.get("metadataUrl") : null;

        SamlMetadataParser.ParsedMetadata parsed;
        if (xml != null && !xml.isBlank()) {
            parsed = metadataParser.parseXml(xml);
        } else if (url != null && !url.isBlank()) {
            parsed = metadataParser.importFromUrl(url);
        } else {
            throw new IllegalArgumentException("Provide metadataXml or metadataUrl");
        }

        if (parsed.kind() != SamlMetadataParser.ParsedKind.SP) {
            throw new IllegalArgumentException(
                    "Metadata describes an IdP, not an SP — use /api/admin/tenants/{id}/saml-providers/import-metadata");
        }
        return ResponseEntity.ok(parsed.spDto());
    }
}
