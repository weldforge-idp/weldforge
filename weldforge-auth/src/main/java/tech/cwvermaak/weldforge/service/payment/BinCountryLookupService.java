package tech.cwvermaak.weldforge.service.payment;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Resolves a credit-card BIN to an ISO 3166-1 alpha-2 country code via
 * binlist.net, cached in-memory for 24 hours.
 *
 * <p>binlist.net is free, rate-limited to 10 requests/minute. We cache
 * aggressively on-success and on-404 to minimise lookups. Network
 * failures return {@link Optional#empty()} — fee calculation then
 * assumes "international" which is the safe, higher-fee default.
 */
@Service
@Slf4j
public class BinCountryLookupService {

    private static final Duration TTL = Duration.ofHours(24);
    private static final Duration HTTP_TIMEOUT = Duration.ofSeconds(3);

    private final Map<String, CachedResult> cache = new ConcurrentHashMap<>();
    private final HttpClient http = HttpClient.newBuilder()
            .connectTimeout(HTTP_TIMEOUT)
            .build();
    private final ObjectMapper mapper = new ObjectMapper();

    /**
     * @param bin first 6–8 digits of a card PAN. Returns empty on lookup
     *            failure, unknown BIN, or malformed input.
     */
    public Optional<String> lookupCountry(String bin) {
        if (bin == null || bin.length() < 6) return Optional.empty();
        String key = bin.substring(0, Math.min(bin.length(), 8));

        CachedResult cached = cache.get(key);
        if (cached != null && cached.expiresAt().isAfter(Instant.now())) {
            return Optional.ofNullable(cached.country());
        }

        Optional<String> fresh = fetchFromBinlist(key);
        cache.put(key, new CachedResult(fresh.orElse(null), Instant.now().plus(TTL)));
        return fresh;
    }

    private Optional<String> fetchFromBinlist(String bin) {
        try {
            HttpRequest req = HttpRequest.newBuilder()
                    .uri(URI.create("https://lookup.binlist.net/" + bin))
                    .timeout(HTTP_TIMEOUT)
                    .header("Accept-Version", "3")
                    .GET()
                    .build();
            HttpResponse<String> resp = http.send(req, HttpResponse.BodyHandlers.ofString());
            if (resp.statusCode() != 200) return Optional.empty();
            JsonNode root = mapper.readTree(resp.body());
            JsonNode alpha2 = root.path("country").path("alpha2");
            if (alpha2.isTextual()) return Optional.of(alpha2.asText().toUpperCase());
            return Optional.empty();
        } catch (Exception e) {
            log.warn("BIN lookup failed for {}: {}", bin, e.getMessage());
            return Optional.empty();
        }
    }

    private record CachedResult(String country, Instant expiresAt) {}
}
