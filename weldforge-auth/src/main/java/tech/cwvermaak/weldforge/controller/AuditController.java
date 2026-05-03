package tech.cwvermaak.weldforge.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import tech.cwvermaak.weldforge.config.tenant.TenantAccessor;
import tech.cwvermaak.weldforge.model.AuditEvent;
import tech.cwvermaak.weldforge.model.dto.AuditEventDto;
import tech.cwvermaak.weldforge.service.audit.AuditService;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Audit log viewer + exporter. Regular admins see only their own tenant's
 * events; super admins can pass {@code tenantId} to drill into any tenant
 * or omit it to see everything.
 */
@RestController
@RequestMapping("/api/admin/audit")
@RequiredArgsConstructor
public class AuditController {

    private final AuditService auditService;
    private final TenantAccessor tenantAccessor;

    @GetMapping
    public ResponseEntity<Map<String, Object>> search(
            @RequestParam(required = false) Long tenantId,
            @RequestParam(required = false) String eventType,
            @RequestParam(required = false) String actorEmail,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) LocalDateTime since,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) LocalDateTime until,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "50") int size) {

        Long scopedTenantId = scopeTenantId(tenantId);
        Page<AuditEvent> result = auditService.search(scopedTenantId, eventType, actorEmail, since, until, page, size);

        return ResponseEntity.ok(Map.of(
                "content", result.getContent().stream().map(AuditEventDto::from).toList(),
                "page", result.getNumber(),
                "size", result.getSize(),
                "totalElements", result.getTotalElements(),
                "totalPages", result.getTotalPages()
        ));
    }

    @GetMapping(value = "/export.csv", produces = "text/csv")
    public ResponseEntity<String> exportCsv(
            @RequestParam(required = false) Long tenantId,
            @RequestParam(required = false) String eventType,
            @RequestParam(required = false) String actorEmail,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) LocalDateTime since,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) LocalDateTime until) {

        Long scopedTenantId = scopeTenantId(tenantId);
        List<AuditEvent> events = auditService.search(scopedTenantId, eventType, actorEmail, since, until, 0, 10_000)
                .getContent();

        String csv = toCsv(events);
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"audit-events.csv\"")
                .contentType(MediaType.parseMediaType("text/csv"))
                .body(csv);
    }

    /**
     * Return the tenant id the search should be limited to. Super admins may
     * optionally provide a tenantId to drill into a specific tenant, or omit
     * it for a cross-tenant view. Regular admins are forced to their own id
     * regardless of what they pass.
     */
    private Long scopeTenantId(Long requestedTenantId) {
        if (tenantAccessor.isSuperAdmin()) {
            return requestedTenantId; // null = all tenants
        }
        return tenantAccessor.requireTenantId();
    }

    private static String toCsv(List<AuditEvent> events) {
        String header = "id,created_at,tenant_slug,actor_email,event_type,outcome,target_type,target_id,ip_address,user_agent";
        String rows = events.stream().map(AuditController::toCsvRow).collect(Collectors.joining("\n"));
        return header + "\n" + rows + "\n";
    }

    private static String toCsvRow(AuditEvent e) {
        return String.join(",",
                String.valueOf(e.getId()),
                csvField(String.valueOf(e.getCreatedAt())),
                csvField(e.getTenant() != null ? e.getTenant().getSlug() : ""),
                csvField(e.getActorEmail()),
                csvField(e.getEventType()),
                csvField(e.getOutcome() != null ? e.getOutcome().name() : ""),
                csvField(e.getTargetType()),
                csvField(e.getTargetId()),
                csvField(e.getIpAddress()),
                csvField(e.getUserAgent())
        );
    }

    private static String csvField(String s) {
        if (s == null) return "";
        if (s.contains(",") || s.contains("\"") || s.contains("\n")) {
            return "\"" + s.replace("\"", "\"\"") + "\"";
        }
        return s;
    }
}
