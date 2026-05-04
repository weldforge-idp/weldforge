package tech.cwvermaak.weldforge.controller;

import jakarta.persistence.EntityNotFoundException;
import lombok.RequiredArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import tech.cwvermaak.weldforge.model.Tenant;
import tech.cwvermaak.weldforge.repository.TenantRepository;
import tech.cwvermaak.weldforge.service.pki.CertificateAuthorityService;
import tech.cwvermaak.weldforge.service.pki.OcspResponderService;

/**
 * Public endpoints for the tenant PKI — CRL distribution (X50-02) and
 * OCSP (X50-05). These have no auth by design: relying parties fetch
 * the CRL or query OCSP without a credential, the same way public CAs
 * operate. The only thing exposed is revocation metadata, never any
 * private material.
 */
@RestController
@RequestMapping("/t/{slug}/pki")
@RequiredArgsConstructor
public class PkiPublicController {

    private final TenantRepository tenantRepository;
    private final CertificateAuthorityService certificateAuthorityService;
    private final OcspResponderService ocspResponderService;

    @GetMapping(value = "/ca.pem", produces = "application/x-pem-file")
    public ResponseEntity<String> caPem(@PathVariable String slug) {
        Tenant tenant = loadTenant(slug);
        return ResponseEntity.ok(certificateAuthorityService.getCaCertificatePem(tenant.getId()));
    }

    @GetMapping(value = "/crl.pem", produces = "application/x-pem-file")
    public ResponseEntity<String> crlPem(@PathVariable String slug) {
        Tenant tenant = loadTenant(slug);
        return ResponseEntity.ok(certificateAuthorityService.generateCrlPem(tenant.getId()));
    }

    @PostMapping(value = "/ocsp",
            consumes = "application/ocsp-request",
            produces = "application/ocsp-response")
    public ResponseEntity<byte[]> ocsp(@PathVariable String slug, @RequestBody byte[] body) {
        Tenant tenant = loadTenant(slug);
        byte[] resp = ocspResponderService.respond(tenant.getId(), body);
        return ResponseEntity.ok()
                .contentType(MediaType.parseMediaType("application/ocsp-response"))
                .body(resp);
    }

    private Tenant loadTenant(String slug) {
        return tenantRepository.findBySlug(slug)
                .orElseThrow(() -> new EntityNotFoundException("Tenant " + slug + " not found"));
    }
}
