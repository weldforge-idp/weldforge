package tech.cwvermaak.weldforge.service.crm;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.resilience4j.circuitbreaker.CallNotPermittedException;
import io.github.resilience4j.circuitbreaker.CircuitBreaker;
import io.github.resilience4j.circuitbreaker.CircuitBreakerRegistry;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import tech.cwvermaak.weldforge.model.CrmProviderType;
import tech.cwvermaak.weldforge.model.TenantCrmProvider;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Map;

/**
 * Production {@link CrmClient}. Builds a vendor-appropriate endpoint URL
 * + auth header from the provider config, POSTs a JSON body, and parses
 * the returned record id where possible.
 *
 * <p>The heavy-lifting Salesforce/HubSpot auth flows (Salesforce OAuth2
 * JWT bearer, HubSpot OAuth2 refresh tokens) are out of scope here — we
 * assume the admin saved a long-lived API/bearer token on the provider
 * row. Swapping in a proper OAuth2 client later is a drop-in on the
 * auth header, nothing else changes.
 */
@Component
@Slf4j
public class HttpCrmClient implements CrmClient {

    private static final String CB_NAME = "crm";

    private final CircuitBreaker circuitBreaker;
    private final ObjectMapper objectMapper;
    private final HttpClient httpClient = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(5))
            .build();

    public HttpCrmClient(CircuitBreakerRegistry registry, ObjectMapper objectMapper) {
        this.circuitBreaker = registry.circuitBreaker(CB_NAME);
        this.objectMapper = objectMapper;
    }

    @Override
    public Result upsert(TenantCrmProvider provider,
                         String existingExternalId,
                         Map<String, Object> fields) {
        try {
            return circuitBreaker.executeSupplier(() -> doUpsert(provider, existingExternalId, fields));
        } catch (CallNotPermittedException cbOpen) {
            log.debug("CRM CB open — skipping push to {}", provider.getProviderType());
            return new Result(false, null, 0, "circuit breaker open");
        } catch (RuntimeException e) {
            return new Result(false, null, 0, e.getMessage());
        }
    }

    private Result doUpsert(TenantCrmProvider provider, String existingExternalId, Map<String, Object> fields) {
        try {
            String url = endpointFor(provider, existingExternalId);
            String method = existingExternalId == null ? "POST" : "PATCH";
            String body = objectMapper.writeValueAsString(fields);

            HttpRequest req = HttpRequest.newBuilder()
                    .uri(URI.create(url))
                    .timeout(Duration.ofSeconds(10))
                    .header("Content-Type", "application/json")
                    .header("Authorization", "Bearer " + provider.getApiToken())
                    .method(method, HttpRequest.BodyPublishers.ofString(body))
                    .build();
            HttpResponse<String> resp = httpClient.send(req, HttpResponse.BodyHandlers.ofString());
            if (resp.statusCode() >= 500) {
                throw new RuntimeException("HTTP " + resp.statusCode());
            }
            if (resp.statusCode() >= 400) {
                return new Result(false, null, resp.statusCode(), resp.body());
            }
            String id = existingExternalId != null
                    ? existingExternalId
                    : extractCreatedId(resp.body());
            return new Result(true, id, resp.statusCode(), null);
        } catch (Exception e) {
            throw new RuntimeException(e.getMessage(), e);
        }
    }

    /**
     * Vendor-specific endpoint path. Kept in one place so the list of
     * supported CRMs can grow without touching the service layer.
     */
    private static String endpointFor(TenantCrmProvider provider, String externalId) {
        String base = provider.getBaseUrl().replaceAll("/$", "");
        CrmProviderType type = provider.getProviderType();
        return switch (type) {
            case SALESFORCE -> externalId == null
                    ? base + "/services/data/v60.0/sobjects/Contact"
                    : base + "/services/data/v60.0/sobjects/Contact/" + externalId;
            case HUBSPOT -> externalId == null
                    ? base + "/crm/v3/objects/contacts"
                    : base + "/crm/v3/objects/contacts/" + externalId;
            case DYNAMICS -> externalId == null
                    ? base + "/api/data/v9.2/contacts"
                    : base + "/api/data/v9.2/contacts(" + externalId + ")";
            case PIPEDRIVE -> externalId == null
                    ? base + "/api/v1/persons"
                    : base + "/api/v1/persons/" + externalId;
        };
    }

    /**
     * Best-effort extraction of the record id from a create response.
     * CRM vendors disagree on the key name — {@code id}, {@code Id},
     * {@code data.id} — so we probe the common shapes and fall back to
     * returning null which the log will record as "created but id
     * unknown".
     */
    private String extractCreatedId(String body) {
        try {
            Map<?, ?> map = objectMapper.readValue(body, Map.class);
            for (String key : new String[]{"id", "Id", "ID"}) {
                Object v = map.get(key);
                if (v != null) return v.toString();
            }
            Object data = map.get("data");
            if (data instanceof Map<?, ?> nested) {
                Object v = nested.get("id");
                if (v != null) return v.toString();
            }
        } catch (Exception ignored) {}
        return null;
    }
}
