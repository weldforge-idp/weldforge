package tech.cwvermaak.weldforge.controller.admin;

import jakarta.persistence.EntityNotFoundException;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import tech.cwvermaak.weldforge.config.tenant.TenantAccessor;
import tech.cwvermaak.weldforge.model.Tenant;
import tech.cwvermaak.weldforge.model.dto.payment.PaymentGatewayDto;
import tech.cwvermaak.weldforge.model.payment.GatewayScope;
import tech.cwvermaak.weldforge.model.payment.PaymentGateway;
import tech.cwvermaak.weldforge.repository.PaymentGatewayRepository;
import tech.cwvermaak.weldforge.repository.TenantRepository;
import tech.cwvermaak.weldforge.service.payment.FeeCalculator;
import tech.cwvermaak.weldforge.service.payment.PaymentRoutingService;
import tech.cwvermaak.weldforge.service.payment.gateway.GatewayCredentials;

import java.util.List;
import java.util.Map;

/**
 * Operator-facing admin CRUD for payment gateways.
 *
 * <p>Two sub-resources:
 * <ul>
 *   <li>{@code /api/admin/payment-gateways} — PLATFORM scope
 *       (WeldForge's own Stripe/Paddle/… keys). SUPER_ADMIN only.</li>
 *   <li>{@code /api/admin/tenants/{tenantId}/payment-gateways} —
 *       TENANT scope (the tenant's own credentials, used when the
 *       tenant bills its end-users). TENANT_ADMIN for the same tenant
 *       or SUPER_ADMIN.</li>
 * </ul>
 *
 * <p>Credentials fields are write-only: create/update accept a
 * plaintext map that is JSON-serialised and then encrypted by the
 * {@code EncryptedStringConverter}; reads never populate them.
 */
@RestController
@RequiredArgsConstructor
public class PaymentGatewayAdminController {

    private final PaymentGatewayRepository gatewayRepository;
    private final TenantRepository tenantRepository;
    private final TenantAccessor tenantAccessor;
    private final PaymentRoutingService routingService;
    private final FeeCalculator feeCalculator;

    // ---- PLATFORM scope -------------------------------------------

    @GetMapping("/api/admin/payment-gateways")
    public List<PaymentGatewayDto> listPlatform() {
        tenantAccessor.requireSuperAdmin();
        return gatewayRepository.findByScopeAndEnabledTrue(GatewayScope.PLATFORM).stream()
                .map(this::toDto).toList();
    }

    @PostMapping("/api/admin/payment-gateways")
    public ResponseEntity<PaymentGatewayDto> createPlatform(@Valid @RequestBody PaymentGatewayDto dto) {
        tenantAccessor.requireSuperAdmin();
        dto.setScope(GatewayScope.PLATFORM);
        dto.setTenantId(null);
        return ResponseEntity.ok(toDto(save(dto, null)));
    }

    @PutMapping("/api/admin/payment-gateways/{id}")
    public PaymentGatewayDto updatePlatform(@PathVariable Long id, @Valid @RequestBody PaymentGatewayDto dto) {
        tenantAccessor.requireSuperAdmin();
        PaymentGateway existing = gatewayRepository.findById(id)
                .filter(g -> g.getScope() == GatewayScope.PLATFORM)
                .orElseThrow(() -> new EntityNotFoundException("Gateway not found"));
        return toDto(update(existing, dto));
    }

    @DeleteMapping("/api/admin/payment-gateways/{id}")
    public ResponseEntity<Void> deletePlatform(@PathVariable Long id) {
        tenantAccessor.requireSuperAdmin();
        PaymentGateway existing = gatewayRepository.findById(id)
                .filter(g -> g.getScope() == GatewayScope.PLATFORM)
                .orElseThrow(() -> new EntityNotFoundException("Gateway not found"));
        gatewayRepository.delete(existing);
        return ResponseEntity.noContent().build();
    }

    // ---- TENANT scope ---------------------------------------------

    @GetMapping("/api/admin/tenants/{tenantId}/payment-gateways")
    public List<PaymentGatewayDto> listTenant(@PathVariable Long tenantId) {
        tenantAccessor.requireSameTenant(tenantId);
        return gatewayRepository.findEnabledTenantGateways(tenantId).stream()
                .map(this::toDto).toList();
    }

    @PostMapping("/api/admin/tenants/{tenantId}/payment-gateways")
    public ResponseEntity<PaymentGatewayDto> createTenant(@PathVariable Long tenantId,
                                                           @Valid @RequestBody PaymentGatewayDto dto) {
        tenantAccessor.requireSameTenant(tenantId);
        Tenant tenant = tenantRepository.findById(tenantId)
                .orElseThrow(() -> new EntityNotFoundException("Tenant not found"));
        dto.setScope(GatewayScope.TENANT);
        dto.setTenantId(tenantId);
        return ResponseEntity.ok(toDto(save(dto, tenant)));
    }

    @PutMapping("/api/admin/tenants/{tenantId}/payment-gateways/{id}")
    public PaymentGatewayDto updateTenant(@PathVariable Long tenantId,
                                           @PathVariable Long id,
                                           @Valid @RequestBody PaymentGatewayDto dto) {
        tenantAccessor.requireSameTenant(tenantId);
        PaymentGateway existing = gatewayRepository.findByIdAndTenantId(id, tenantId)
                .orElseThrow(() -> new EntityNotFoundException("Gateway not found"));
        return toDto(update(existing, dto));
    }

    @DeleteMapping("/api/admin/tenants/{tenantId}/payment-gateways/{id}")
    public ResponseEntity<Void> deleteTenant(@PathVariable Long tenantId, @PathVariable Long id) {
        tenantAccessor.requireSameTenant(tenantId);
        PaymentGateway existing = gatewayRepository.findByIdAndTenantId(id, tenantId)
                .orElseThrow(() -> new EntityNotFoundException("Gateway not found"));
        gatewayRepository.delete(existing);
        return ResponseEntity.noContent().build();
    }

    // ---- Rate comparison preview ----------------------------------

    /**
     * Preview the current cheapest→most-expensive ranking for a
     * hypothetical transaction. Operators use this to validate their
     * gateway config before a real customer encounters it.
     */
    @GetMapping("/api/admin/payment-gateways/rate-preview")
    public List<Map<String, Object>> ratePreview(@RequestParam long amountCents,
                                                  @RequestParam String currency,
                                                  @RequestParam(required = false) String billingCountry,
                                                  @RequestParam(required = false) String cardCountry) {
        tenantAccessor.requireSuperAdmin();
        return routingService
                .rankPlatform(amountCents, currency, billingCountry, cardCountry)
                .stream()
                .map(q -> Map.<String, Object>of(
                        "gatewayId", q.gateway().getId(),
                        "provider",  q.gateway().getProvider().name(),
                        "displayName", q.gateway().getDisplayName(),
                        "feeCents",  q.feeCents(),
                        "feeDisplay", String.format("%s %.2f",
                                currency.toUpperCase(),
                                q.feeCents() / 100.0)))
                .toList();
    }

    // ---- Mapping helpers ------------------------------------------

    private PaymentGateway save(PaymentGatewayDto dto, Tenant tenant) {
        PaymentGateway g = PaymentGateway.builder()
                .scope(dto.getScope())
                .tenant(tenant)
                .provider(dto.getProvider())
                .displayName(dto.getDisplayName())
                .enabled(dto.isEnabled())
                .priority(dto.getPriority())
                .supportedCurrencies(dto.getSupportedCurrencies())
                .supportedCountries(dto.getSupportedCountries())
                .config(dto.getConfig() == null ? Map.of() : dto.getConfig())
                .credentialsEncrypted(GatewayCredentials.encode(
                        dto.getCredentials() == null ? Map.of() : dto.getCredentials()))
                .feeStructure(dto.getFeeStructure())
                .build();
        return gatewayRepository.save(g);
    }

    private PaymentGateway update(PaymentGateway existing, PaymentGatewayDto dto) {
        existing.setDisplayName(dto.getDisplayName());
        existing.setEnabled(dto.isEnabled());
        existing.setPriority(dto.getPriority());
        if (dto.getSupportedCurrencies() != null) existing.setSupportedCurrencies(dto.getSupportedCurrencies());
        existing.setSupportedCountries(dto.getSupportedCountries());
        if (dto.getConfig() != null) existing.setConfig(dto.getConfig());
        if (dto.getFeeStructure() != null) existing.setFeeStructure(dto.getFeeStructure());
        // Credentials are only overwritten if a fresh map was supplied —
        // an update call that omits credentials preserves the existing row.
        if (dto.getCredentials() != null && !dto.getCredentials().isEmpty()) {
            existing.setCredentialsEncrypted(GatewayCredentials.encode(dto.getCredentials()));
        }
        return gatewayRepository.save(existing);
    }

    private PaymentGatewayDto toDto(PaymentGateway g) {
        return PaymentGatewayDto.builder()
                .id(g.getId())
                .scope(g.getScope())
                .tenantId(g.getTenant() == null ? null : g.getTenant().getId())
                .provider(g.getProvider())
                .displayName(g.getDisplayName())
                .enabled(g.isEnabled())
                .priority(g.getPriority())
                .supportedCurrencies(g.getSupportedCurrencies())
                .supportedCountries(g.getSupportedCountries())
                .config(g.getConfig())
                .feeStructure(g.getFeeStructure())
                // credentials never populated on reads
                .build();
    }
}
