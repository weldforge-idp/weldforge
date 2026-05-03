package tech.cwvermaak.weldforge.service;

import com.twilio.http.TwilioRestClient;
import com.twilio.rest.api.v2010.account.Message;
import com.twilio.type.PhoneNumber;
import io.github.resilience4j.circuitbreaker.CallNotPermittedException;
import io.github.resilience4j.circuitbreaker.CircuitBreaker;
import io.github.resilience4j.circuitbreaker.CircuitBreakerRegistry;
import jakarta.persistence.EntityNotFoundException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import tech.cwvermaak.weldforge.model.Tenant;
import tech.cwvermaak.weldforge.model.TenantTwilioProvider;
import tech.cwvermaak.weldforge.repository.TenantTwilioProviderRepository;
import tech.cwvermaak.weldforge.service.resilience.ProviderUnavailableException;

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
@Slf4j
public class TwilioService {

    private static final String CB_NAME = "twilio";

    private final TenantTwilioProviderRepository repository;
    private final CircuitBreaker circuitBreaker;

    private final Map<String, TwilioRestClient> clientCache = new ConcurrentHashMap<>();

    public TwilioService(TenantTwilioProviderRepository repository,
                         CircuitBreakerRegistry registry) {
        this.repository = repository;
        this.circuitBreaker = registry.circuitBreaker(CB_NAME);
    }

    /**
     * Send an SMS to {@code to} using the calling tenant's Twilio config.
     * Throws {@link IllegalStateException} if the tenant has no Twilio
     * configuration or it's disabled.
     */
    public void sendSms(Tenant tenant, String to, String messageBody) {
        TenantTwilioProvider config = requireEnabledConfig(tenant);
        TwilioRestClient client = clientFor(tenant.getId(), config);

        runInCircuitBreaker("SMS", tenant, () ->
                Message.creator(
                        new PhoneNumber(to),
                        new PhoneNumber(config.getFromPhone()),
                        messageBody
                ).create(client));
    }

    /**
     * Send a WhatsApp message using the calling tenant's Twilio config.
     * Requires the tenant's caller-id number to be WhatsApp-enabled in
     * their Twilio console.
     */
    public void sendWhatsApp(Tenant tenant, String to, String messageBody) {
        TenantTwilioProvider config = requireEnabledConfig(tenant);
        TwilioRestClient client = clientFor(tenant.getId(), config);

        runInCircuitBreaker("WhatsApp", tenant, () ->
                Message.creator(
                        new PhoneNumber("whatsapp:" + to),
                        new PhoneNumber("whatsapp:" + config.getFromPhone()),
                        messageBody
                ).create(client));
    }

    /**
     * Execute the Twilio API call inside the {@code twilio} circuit
     * breaker (PRD AVL-04). A CallNotPermittedException means the CB is
     * open — we translate it into a tagged {@link ProviderUnavailableException}
     * so callers and the global handler can return a clean
     * "SMS temporarily unavailable" response instead of a 500.
     */
    private void runInCircuitBreaker(String channel, Tenant tenant, Runnable call) {
        try {
            circuitBreaker.executeRunnable(call);
        } catch (CallNotPermittedException cbOpen) {
            log.warn("Twilio CB open — rejecting {} for tenant {}", channel, tenant.getSlug());
            throw new ProviderUnavailableException(CB_NAME,
                    "Twilio " + channel + " is temporarily unavailable, please retry shortly");
        } catch (Exception e) {
            log.error("Twilio {} send failed for tenant {}: {}", channel, tenant.getSlug(), e.getMessage());
            throw new IllegalStateException("Failed to send " + channel + " via Twilio: " + e.getMessage(), e);
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
