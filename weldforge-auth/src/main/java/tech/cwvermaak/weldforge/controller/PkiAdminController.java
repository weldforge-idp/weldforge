package tech.cwvermaak.weldforge.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import tech.cwvermaak.weldforge.model.IssuedCertificate;
import tech.cwvermaak.weldforge.model.dto.CertificateAuthorityDto;
import tech.cwvermaak.weldforge.model.dto.IssuedCertificateDto;
import tech.cwvermaak.weldforge.service.pki.CertificateAuthorityService;

import java.util.List;
import java.util.Map;

/**
 * Admin API for the per-tenant PKI module (PRD §3.6). All endpoints
 * live under {@code /api/admin/pki} and are guarded by the existing
 * admin chain + the service-level {@code TenantAccessor} checks.
 */
@RestController
@RequestMapping("/api/admin/pki")
@RequiredArgsConstructor
public class PkiAdminController {

    private final CertificateAuthorityService caService;

    // ---- CA lifecycle ---------------------------------------------

    @PostMapping("/ca")
    public ResponseEntity<CertificateAuthorityDto> createCa(@RequestBody(required = false) Map<String, Object> body) {
        Integer years = body == null ? null : (Integer) body.get("yearsValid");
        return ResponseEntity.ok(caService.createRootCa(years));
    }

    @GetMapping("/ca")
    public ResponseEntity<CertificateAuthorityDto> getCa() {
        return ResponseEntity.ok(caService.getCa());
    }

    // ---- End-entity certs -----------------------------------------

    @GetMapping("/certificates")
    public ResponseEntity<List<IssuedCertificateDto>> list() {
        return ResponseEntity.ok(caService.listCertificates());
    }

    @PostMapping("/certificates")
    public ResponseEntity<IssuedCertificateDto> issue(@RequestBody IssuedCertificateDto dto) {
        return ResponseEntity.ok(caService.issueCertificate(dto));
    }

    @PostMapping("/certificates/{serial}/revoke")
    public ResponseEntity<Void> revoke(@PathVariable String serial,
                                        @RequestBody(required = false) Map<String, String> body) {
        IssuedCertificate.RevocationReason reason =
                body == null || body.get("reason") == null
                        ? IssuedCertificate.RevocationReason.UNSPECIFIED
                        : IssuedCertificate.RevocationReason.valueOf(body.get("reason"));
        caService.revokeCertificate(serial, reason);
        return ResponseEntity.noContent().build();
    }
}
