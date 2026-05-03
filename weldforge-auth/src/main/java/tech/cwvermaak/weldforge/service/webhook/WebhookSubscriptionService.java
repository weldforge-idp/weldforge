package tech.cwvermaak.weldforge.service.webhook;

import jakarta.persistence.EntityNotFoundException;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import tech.cwvermaak.weldforge.config.tenant.TenantAccessor;
import tech.cwvermaak.weldforge.model.Tenant;
import tech.cwvermaak.weldforge.model.WebhookSubscription;
import tech.cwvermaak.weldforge.model.dto.WebhookSubscriptionDto;
import tech.cwvermaak.weldforge.repository.WebhookSubscriptionRepository;

import java.security.SecureRandom;
import java.util.HexFormat;
import java.util.List;

/**
 * Admin CRUD for webhook subscriptions (PRD API-05). Tenant-isolated via
 * {@link TenantAccessor}; secret values are generated server-side and
 * returned to the caller once on create/rotate.
 */
@Service
@RequiredArgsConstructor
public class WebhookSubscriptionService {

    private static final SecureRandom RNG = new SecureRandom();

    private final TenantAccessor tenantAccessor;
    private final WebhookSubscriptionRepository repository;

    @Transactional(readOnly = true)
    public List<WebhookSubscriptionDto> list() {
        tenantAccessor.requireAnyAdmin();
        Long tid = tenantAccessor.requireTenantId();
        return repository.findByTenantId(tid).stream()
                .map(WebhookSubscriptionService::toMaskedDto)
                .toList();
    }

    @Transactional
    public WebhookSubscriptionDto create(WebhookSubscriptionDto dto) {
        tenantAccessor.requireTenantAdmin();
        if (dto.getName() == null || dto.getName().isBlank()) {
            throw new IllegalArgumentException("Webhook subscription name is required");
        }
        if (dto.getTargetUrl() == null || dto.getTargetUrl().isBlank()) {
            throw new IllegalArgumentException("targetUrl is required");
        }
        Tenant tenant = tenantAccessor.requireTenant();
        String secret = generateSecret();

        WebhookSubscription sub = WebhookSubscription.builder()
                .tenant(tenant)
                .name(dto.getName().trim())
                .targetUrl(dto.getTargetUrl().trim())
                .secret(secret)
                .eventFilters(dto.getEventFilters())
                .enabled(dto.getEnabled() == null || dto.getEnabled())
                .maxAttempts(dto.getMaxAttempts() == null ? 6 : dto.getMaxAttempts())
                .build();
        WebhookSubscription saved = repository.save(sub);

        WebhookSubscriptionDto out = toMaskedDto(saved);
        out.setSecret(secret); // single-reveal
        return out;
    }

    @Transactional
    public WebhookSubscriptionDto update(Long id, WebhookSubscriptionDto dto) {
        tenantAccessor.requireTenantAdmin();
        WebhookSubscription sub = loadOwn(id);
        if (dto.getName() != null) sub.setName(dto.getName().trim());
        if (dto.getTargetUrl() != null) sub.setTargetUrl(dto.getTargetUrl().trim());
        if (dto.getEventFilters() != null) sub.setEventFilters(dto.getEventFilters());
        if (dto.getEnabled() != null) sub.setEnabled(dto.getEnabled());
        if (dto.getMaxAttempts() != null) sub.setMaxAttempts(dto.getMaxAttempts());
        return toMaskedDto(sub);
    }

    @Transactional
    public WebhookSubscriptionDto rotate(Long id) {
        tenantAccessor.requireTenantAdmin();
        WebhookSubscription sub = loadOwn(id);
        String secret = generateSecret();
        sub.setSecret(secret);
        WebhookSubscriptionDto out = toMaskedDto(sub);
        out.setSecret(secret);
        return out;
    }

    @Transactional
    public void delete(Long id) {
        tenantAccessor.requireTenantAdmin();
        repository.delete(loadOwn(id));
    }

    private WebhookSubscription loadOwn(Long id) {
        Long tid = tenantAccessor.requireTenantId();
        return repository.findByIdAndTenantId(id, tid)
                .orElseThrow(() -> new EntityNotFoundException("Webhook subscription " + id + " not found"));
    }

    private static WebhookSubscriptionDto toMaskedDto(WebhookSubscription s) {
        return WebhookSubscriptionDto.builder()
                .id(s.getId())
                .name(s.getName())
                .targetUrl(s.getTargetUrl())
                .eventFilters(s.getEventFilters())
                .enabled(s.isEnabled())
                .maxAttempts(s.getMaxAttempts())
                .build();
    }

    private static String generateSecret() {
        byte[] buf = new byte[32];
        RNG.nextBytes(buf);
        return "whsec_" + HexFormat.of().formatHex(buf);
    }
}
