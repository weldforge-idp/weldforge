package tech.cwvermaak.intellisso.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import tech.cwvermaak.intellisso.model.SocialProviderType;
import tech.cwvermaak.intellisso.model.dto.SamlProviderDto;
import tech.cwvermaak.intellisso.model.dto.SocialProviderDto;
import tech.cwvermaak.intellisso.model.dto.TenantDto;
import tech.cwvermaak.intellisso.model.dto.TwilioProviderDto;
import tech.cwvermaak.intellisso.service.TenantSamlService;
import tech.cwvermaak.intellisso.service.TenantService;
import tech.cwvermaak.intellisso.service.TenantTwilioService;

import java.util.List;

/**
 * Administration of tenants and their per-tenant social provider config.
 * All endpoints sit under /api/admin so they're behind the authenticated
 * admin chain.
 */
@RestController
@RequestMapping("/api/admin/tenants")
@RequiredArgsConstructor
public class TenantController {

    private final TenantService tenantService;
    private final TenantSamlService tenantSamlService;
    private final TenantTwilioService tenantTwilioService;

    @GetMapping
    public ResponseEntity<List<TenantDto>> list() {
        return ResponseEntity.ok(tenantService.listTenants());
    }

    @GetMapping("/{id}")
    public ResponseEntity<TenantDto> get(@PathVariable Long id) {
        return ResponseEntity.ok(tenantService.getTenant(id));
    }

    @PostMapping
    public ResponseEntity<TenantDto> create(@RequestBody TenantDto dto) {
        return ResponseEntity.ok(tenantService.createTenant(dto));
    }

    @PutMapping("/{id}")
    public ResponseEntity<TenantDto> update(@PathVariable Long id, @RequestBody TenantDto dto) {
        return ResponseEntity.ok(tenantService.updateTenant(id, dto));
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> delete(@PathVariable Long id) {
        tenantService.deleteTenant(id);
        return ResponseEntity.noContent().build();
    }

    // -- Social providers ---------------------------------------------

    @GetMapping("/{id}/social-providers")
    public ResponseEntity<List<SocialProviderDto>> listProviders(@PathVariable Long id) {
        return ResponseEntity.ok(tenantService.listProviders(id));
    }

    /**
     * Upsert — POST creates or updates the provider row for (tenant, provider).
     * This keeps the admin UX simple: one row per (tenant, provider) enforced
     * by the DB unique constraint, and callers don't need to track IDs.
     */
    @PostMapping("/{id}/social-providers")
    public ResponseEntity<SocialProviderDto> upsertProvider(
            @PathVariable Long id,
            @RequestBody SocialProviderDto dto) {
        return ResponseEntity.ok(tenantService.upsertProvider(id, dto));
    }

    @DeleteMapping("/{id}/social-providers/{provider}")
    public ResponseEntity<Void> deleteProvider(
            @PathVariable Long id,
            @PathVariable SocialProviderType provider) {
        tenantService.deleteProvider(id, provider);
        return ResponseEntity.noContent().build();
    }

    // -- SAML providers -----------------------------------------------

    @GetMapping("/{id}/saml-providers")
    public ResponseEntity<List<SamlProviderDto>> listSamlProviders(@PathVariable Long id) {
        return ResponseEntity.ok(tenantSamlService.list(id));
    }

    @PostMapping("/{id}/saml-providers")
    public ResponseEntity<SamlProviderDto> upsertSamlProvider(
            @PathVariable Long id,
            @RequestBody SamlProviderDto dto) {
        return ResponseEntity.ok(tenantSamlService.upsert(id, dto));
    }

    @DeleteMapping("/{id}/saml-providers/{providerKey}")
    public ResponseEntity<Void> deleteSamlProvider(
            @PathVariable Long id,
            @PathVariable String providerKey) {
        tenantSamlService.delete(id, providerKey);
        return ResponseEntity.noContent().build();
    }

    // -- Twilio provider ----------------------------------------------

    @GetMapping("/{id}/twilio")
    public ResponseEntity<TwilioProviderDto> getTwilio(@PathVariable Long id) {
        TwilioProviderDto dto = tenantTwilioService.get(id);
        return dto == null ? ResponseEntity.noContent().build() : ResponseEntity.ok(dto);
    }

    @PostMapping("/{id}/twilio")
    public ResponseEntity<TwilioProviderDto> upsertTwilio(
            @PathVariable Long id,
            @RequestBody TwilioProviderDto dto) {
        return ResponseEntity.ok(tenantTwilioService.upsert(id, dto));
    }

    @PutMapping("/{id}/twilio")
    public ResponseEntity<TwilioProviderDto> updateTwilio(
            @PathVariable Long id,
            @RequestBody TwilioProviderDto dto) {
        return ResponseEntity.ok(tenantTwilioService.upsert(id, dto));
    }

    @DeleteMapping("/{id}/twilio")
    public ResponseEntity<Void> deleteTwilio(@PathVariable Long id) {
        tenantTwilioService.delete(id);
        return ResponseEntity.noContent().build();
    }
}
