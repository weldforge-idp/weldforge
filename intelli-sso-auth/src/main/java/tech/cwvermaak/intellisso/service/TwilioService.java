package tech.cwvermaak.intellisso.service;

import com.twilio.http.TwilioRestClient;
import com.twilio.rest.api.v2010.account.Message;
import com.twilio.type.PhoneNumber;
import jakarta.persistence.EntityNotFoundException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import tech.cwvermaak.intellisso.model.Tenant;
import tech.cwvermaak.intellisso.model.TenantTwilioProvider;
import tech.cwvermaak.intellisso.repository.TenantTwilioProviderRepository;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Tenant-aware SMS/WhatsApp dispatcher via Twilio. Credentials are loaded
 * from {@link TenantTwilioProvider} at call time rather than from global
 * env vars — each tenant uses its own Twilio subaccount with its own
 * caller-id number.
 *
 * The Twilio Java SDK exposes a process-wide static {@code Twilio.init()}
 * which is incompatible with multi-tenant credentials. We bypass it by
 * constructing a {@link TwilioRestClient} per tenant and caching them
 * keyed on (tenantId, accountSid) so a credential rotation invalidates
 * the cache entry automatically.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class TwilioService {

    private final TenantTwilioProviderRepository repository;

    private final Map<String, TwilioRestClient> clientCache = new ConcurrentHashMap<>();

    /**
     * Send an SMS to {@code to} using the calling tenant's Twilio config.
     * Throws {@link IllegalStateException} if the tenant has no Twilio
     * configuration or it's disabled.
     */
    public void sendSms(Tenant tenant, String to, String messageBody) {
        TenantTwilioProvider config = requireEnabledConfig(tenant);
        TwilioRestClient client = clientFor(tenant.getId(), config);

        try {
            Message.creator(
                    new PhoneNumber(to),
                    new PhoneNumber(config.getFromPhone()),
                    messageBody
            ).create(client);
        } catch (Exception e) {
            log.error("Twilio SMS send failed for tenant {}: {}", tenant.getSlug(), e.getMessage());
            throw new IllegalStateException("Failed to send SMS via Twilio: " + e.getMessage(), e);
        }
    }

    /**
     * Send a WhatsApp message using the calling tenant's Twilio config.
     * Requires the tenant's caller-id number to be WhatsApp-enabled in
     * their Twilio console.
     */
    public void sendWhatsApp(Tenant tenant, String to, String messageBody) {
        TenantTwilioProvider config = requireEnabledConfig(tenant);
        TwilioRestClient client = clientFor(tenant.getId(), config);

        try {
            Message.creator(
                    new PhoneNumber("whatsapp:" + to),
                    new PhoneNumber("whatsapp:" + config.getFromPhone()),
                    messageBody
            ).create(client);
        } catch (Exception e) {
            log.error("Twilio WhatsApp send failed for tenant {}: {}", tenant.getSlug(), e.getMessage());
            throw new IllegalStateException("Failed to send WhatsApp via Twilio: " + e.getMessage(), e);
        }
    }

    /** Evict the cached client for a tenant — call after credential rotation. */
    public void invalidateCache(Long tenantId) {
        clientCache.keySet().removeIf(k -> k.startsWith(tenantId + ":"));
    }

    // ---- Internals --------------------------------------------------

    private TenantTwilioProvider requireEnabledConfig(Tenant tenant) {
        if (tenant == null) {
            throw new IllegalStateException("Cannot send SMS without a tenant");
        }
        return repository.findByTenantIdAndEnabledTrue(tenant.getId())
                .orElseThrow(() -> new EntityNotFoundException(
                        "No enabled Twilio config for tenant " + tenant.getSlug()));
    }

    private TwilioRestClient clientFor(Long tenantId, TenantTwilioProvider config) {
        String key = tenantId + ":" + config.getAccountSid();
        return clientCache.computeIfAbsent(key, k ->
                new TwilioRestClient.Builder(config.getAccountSid(), config.getAuthToken()).build());
    }
}
