package tech.cwvermaak.weldforge.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import tech.cwvermaak.weldforge.config.tenant.TenantAccessor;
import tech.cwvermaak.weldforge.model.dto.SamlServiceProviderDto;
import tech.cwvermaak.weldforge.service.saml.SamlIdpService;
import tech.cwvermaak.weldforge.service.saml.SamlMetadataParser;

import java.util.List;
import java.util.Map;

/**
 * Admin CRUD for downstream SAML Service Provider registrations, nested
 * under the owning tenant ({@code /api/admin/tenants/{tenantId}/saml/service-providers}).
 * Tenant isolation is enforced inside {@link SamlIdpService} via
 * {@code TenantAccessor.requireSameTenant(tenantId)}; SUPER_ADMIN may
 * target a foreign tenant.
 *
 * The metadata-import endpoint is also nested for symmetry — the parsed
 * SP shape may include tenant-scoped defaults later, and keeping every
 * admin sub-resource under {@code /tenants/{tenantId}/...} makes the
 * RBAC story uniform across the API surface.
 */
@RestController
@RequestMapping("/api/admin/tenants/{tenantId}/saml/service-providers")
@RequiredArgsConstructor
public class SamlIdpAdminController {

    private final SamlIdpService samlIdpService;
    private final SamlMetadataParser metadataParser;
    private final TenantAccessor tenantAccessor;

    @GetMapping
    public ResponseEntity<List<SamlServiceProviderDto>> list(@PathVariable Long tenantId) {
        return ResponseEntity.ok(samlIdpService.list(tenantId));
    }

    @PostMapping
    public ResponseEntity<SamlServiceProviderDto> create(@PathVariable Long tenantId,
                                                          @RequestBody SamlServiceProviderDto dto) {
        return ResponseEntity.ok(samlIdpService.create(tenantId, dto));
    }

    @PutMapping("/{id}")
    public ResponseEntity<SamlServiceProviderDto> update(@PathVariable Long tenantId,
                                                          @PathVariable Long id,
                                                          @RequestBody SamlServiceProviderDto dto) {
        return ResponseEntity.ok(samlIdpService.update(tenantId, id, dto));
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> delete(@PathVariable Long tenantId, @PathVariable Long id) {
        samlIdpService.delete(tenantId, id);
        return ResponseEntity.noContent().build();
    }

    /**
     * PRD SAM-05: parse SAML metadata (either pasted XML or fetched from a
     * URL) and return a populated {@link SamlServiceProviderDto} that the
     * admin portal pre-fills into the create form. This is a read-only
     * parse — nothing is persisted until the admin hits Create. Tenant
     * isolation is still enforced because the URL nests the resource
     * under the target tenant.
     */
    @PostMapping("/import-metadata")
    public ResponseEntity<SamlServiceProviderDto> importMetadata(
            @PathVariable Long tenantId,
            @RequestBody Map<String, String> body) {
        tenantAccessor.requireTenantAdmin();
        tenantAccessor.requireSameTenant(tenantId);

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
