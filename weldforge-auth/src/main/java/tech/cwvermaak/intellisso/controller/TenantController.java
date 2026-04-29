package tech.cwvermaak.intellisso.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import tech.cwvermaak.intellisso.model.SocialProviderType;
import tech.cwvermaak.intellisso.model.dto.SamlProviderDto;
import tech.cwvermaak.intellisso.model.dto.SocialProviderDto;
import tech.cwvermaak.intellisso.model.dto.TenantDto;
import tech.cwvermaak.intellisso.model.dto.CrmProviderDto;
import tech.cwvermaak.intellisso.model.dto.FederationRulesDto;
import tech.cwvermaak.intellisso.model.dto.LdapProviderDto;
import tech.cwvermaak.intellisso.model.dto.MfaPolicyDto;
import tech.cwvermaak.intellisso.model.dto.TwilioProviderDto;
import tech.cwvermaak.intellisso.service.TenantMfaPolicyService;
import tech.cwvermaak.intellisso.service.TenantSamlService;
import tech.cwvermaak.intellisso.service.TenantService;
import tech.cwvermaak.intellisso.service.TenantTwilioService;
import tech.cwvermaak.intellisso.service.crm.TenantCrmService;
import tech.cwvermaak.intellisso.service.federation.TenantFederationRulesService;
import tech.cwvermaak.intellisso.service.ldap.TenantLdapService;
import tech.cwvermaak.intellisso.service.saml.SamlMetadataParser;

import java.util.List;
import java.util.Map;

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
    private final TenantMfaPolicyService tenantMfaPolicyService;
    private final TenantFederationRulesService tenantFederationRulesService;
    private final TenantLdapService tenantLdapService;
    private final TenantCrmService tenantCrmService;
    private final SamlMetadataParser samlMetadataParser;

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

    /**
     * PRD SAM-05: import an upstream IdP's metadata by pasted XML or URL.
     * Returns a populated {@link SamlProviderDto} with idpEntityId,
     * idpSsoUrl, idpSloUrl, and the signing certificate extracted. The
     * admin reviews and submits the create form as usual.
     */
    @PostMapping("/{id}/saml-providers/import-metadata")
    public ResponseEntity<SamlProviderDto> importSamlProviderMetadata(
            @PathVariable Long id,
            @RequestBody Map<String, String> body) {
        String xml = body != null ? body.get("metadataXml") : null;
        String url = body != null ? body.get("metadataUrl") : null;

        SamlMetadataParser.ParsedMetadata parsed;
        if (xml != null && !xml.isBlank()) {
            parsed = samlMetadataParser.parseXml(xml);
        } else if (url != null && !url.isBlank()) {
            parsed = samlMetadataParser.importFromUrl(url);
        } else {
            throw new IllegalArgumentException("Provide metadataXml or metadataUrl");
        }

        if (parsed.kind() != SamlMetadataParser.ParsedKind.IDP) {
            throw new IllegalArgumentException(
                    "Metadata describes an SP, not an IdP — use /api/admin/saml/service-providers/import-metadata");
        }
        // tenantId is set at persistence time; the DTO returned here is a
        // pre-fill for the form, not yet bound to a specific tenant row.
        SamlProviderDto dto = parsed.idpDto();
        dto.setTenantId(id);
        return ResponseEntity.ok(dto);
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

    // -- MFA policy (MFA-03 / MFA-04 / SSO-05) ------------------------

    @GetMapping("/{id}/mfa-policy")
    public ResponseEntity<MfaPolicyDto> getMfaPolicy(@PathVariable Long id) {
        return ResponseEntity.ok(tenantMfaPolicyService.get(id));
    }

    @PostMapping("/{id}/mfa-policy")
    public ResponseEntity<MfaPolicyDto> upsertMfaPolicy(
            @PathVariable Long id,
            @RequestBody MfaPolicyDto dto) {
        return ResponseEntity.ok(tenantMfaPolicyService.upsert(id, dto));
    }

    @PutMapping("/{id}/mfa-policy")
    public ResponseEntity<MfaPolicyDto> updateMfaPolicy(
            @PathVariable Long id,
            @RequestBody MfaPolicyDto dto) {
        return ResponseEntity.ok(tenantMfaPolicyService.upsert(id, dto));
    }

    // -- Federation rules (PRD FED-02 / FED-04) -----------------------

    @GetMapping("/{id}/federation-rules")
    public ResponseEntity<FederationRulesDto> getFederationRules(@PathVariable Long id) {
        return ResponseEntity.ok(tenantFederationRulesService.get(id));
    }

    @PostMapping("/{id}/federation-rules")
    public ResponseEntity<FederationRulesDto> upsertFederationRules(
            @PathVariable Long id,
            @RequestBody FederationRulesDto dto) {
        return ResponseEntity.ok(tenantFederationRulesService.upsert(id, dto));
    }

    @PutMapping("/{id}/federation-rules")
    public ResponseEntity<FederationRulesDto> updateFederationRules(
            @PathVariable Long id,
            @RequestBody FederationRulesDto dto) {
        return ResponseEntity.ok(tenantFederationRulesService.upsert(id, dto));
    }

    // -- LDAP / AD providers (PRD DIR-01 / DIR-02) --------------------

    @GetMapping("/{id}/ldap-providers")
    public ResponseEntity<List<LdapProviderDto>> listLdap(@PathVariable Long id) {
        return ResponseEntity.ok(tenantLdapService.list(id));
    }

    @PostMapping("/{id}/ldap-providers")
    public ResponseEntity<LdapProviderDto> createLdap(@PathVariable Long id,
                                                       @RequestBody LdapProviderDto dto) {
        return ResponseEntity.ok(tenantLdapService.create(id, dto));
    }

    @PutMapping("/{id}/ldap-providers/{providerId}")
    public ResponseEntity<LdapProviderDto> updateLdap(@PathVariable Long id,
                                                       @PathVariable Long providerId,
                                                       @RequestBody LdapProviderDto dto) {
        return ResponseEntity.ok(tenantLdapService.update(id, providerId, dto));
    }

    @DeleteMapping("/{id}/ldap-providers/{providerId}")
    public ResponseEntity<Void> deleteLdap(@PathVariable Long id,
                                            @PathVariable Long providerId) {
        tenantLdapService.delete(id, providerId);
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/{id}/ldap-providers/{providerId}/test-connection")
    public ResponseEntity<Map<String, Object>> testLdap(@PathVariable Long id,
                                                         @PathVariable Long providerId) {
        boolean ok = tenantLdapService.testConnection(id, providerId);
        return ResponseEntity.ok(Map.of("success", ok));
    }

    // -- CRM providers (PRD §3.10 CRM-01..CRM-04) ---------------------

    @GetMapping("/{id}/crm-providers")
    public ResponseEntity<List<CrmProviderDto>> listCrm(@PathVariable Long id) {
        return ResponseEntity.ok(tenantCrmService.list(id));
    }

    @PostMapping("/{id}/crm-providers")
    public ResponseEntity<CrmProviderDto> createCrm(@PathVariable Long id,
                                                     @RequestBody CrmProviderDto dto) {
        return ResponseEntity.ok(tenantCrmService.create(id, dto));
    }

    @PutMapping("/{id}/crm-providers/{providerId}")
    public ResponseEntity<CrmProviderDto> updateCrm(@PathVariable Long id,
                                                     @PathVariable Long providerId,
                                                     @RequestBody CrmProviderDto dto) {
        return ResponseEntity.ok(tenantCrmService.update(id, providerId, dto));
    }

    @DeleteMapping("/{id}/crm-providers/{providerId}")
    public ResponseEntity<Void> deleteCrm(@PathVariable Long id,
                                           @PathVariable Long providerId) {
        tenantCrmService.delete(id, providerId);
        return ResponseEntity.noContent().build();
    }
}
