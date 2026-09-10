package tech.cwvermaak.weldforge.service.security;

import io.micrometer.core.instrument.MeterRegistry;
import lombok.extern.slf4j.Slf4j;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.HexFormat;
import java.util.function.Function;

/**
 * {@link BreachedPasswordScreen} backed by the Pwned Passwords range API
 * (k-anonymity).
 *
 * <p><b>The password never leaves the server.</b> Only the first five hex
 * characters of its SHA-1 are sent; the corpus answers with every suffix that
 * shares that prefix (hundreds of them, padded with decoys when
 * {@code Add-Padding} is set so the response size does not narrow it down),
 * and the match happens here. The prefix is shared by roughly a million
 * possible passwords, so it identifies none of them. SHA-1 is the corpus's
 * index format, not a password hash -- nothing hashed here is stored.
 *
 * <p><b>Fails open.</b> Any failure -- timeout, non-200, a URL the egress guard
 * refuses -- is {@link Result#UNAVAILABLE}: logged at WARN and counted on
 * {@code sso.password.breach_check{outcome=unavailable}}, but the password is
 * not refused for it. A third-party outage must not block every registration
 * and password reset on the platform; the counter is how an operator notices
 * screening has quietly stopped.
 */
@Slf4j
public class PwnedPasswordsScreen implements BreachedPasswordScreen {

    public static final String DEFAULT_RANGE_URL = "https://api.pwnedpasswords.com/range/";

    private final String rangeUrl;
    private final Function<String, String> rangeFetcher;
    private final MeterRegistry meterRegistry;

    /** Production wiring: an HTTPS client, guarded by {@link EgressGuard}. */
    public PwnedPasswordsScreen(String rangeUrl, Duration timeout, MeterRegistry meterRegistry) {
        this(rangeUrl, httpFetcher(rangeUrl, timeout), meterRegistry);
    }

    /**
     * @param rangeFetcher given the five-character prefix, returns the range
     *                     body -- or throws. Visible so tests can observe
     *                     exactly what would be sent.
     */
    PwnedPasswordsScreen(String rangeUrl, Function<String, String> rangeFetcher,
                         MeterRegistry meterRegistry) {
        this.rangeUrl = rangeUrl;
        this.rangeFetcher = rangeFetcher;
        this.meterRegistry = meterRegistry;
    }

    @Override
    public Result check(String password) {
        String hash = sha1Hex(password);
        String prefix = hash.substring(0, 5);
        String suffix = hash.substring(5);

        Result result;
        try {
            result = containsSuffix(rangeFetcher.apply(prefix), suffix) ? Result.BREACHED : Result.CLEAN;
        } catch (RuntimeException e) {
            log.warn("Breached-password screening unavailable, failing open: url={} cause={}",
                    rangeUrl, e.toString());
            result = Result.UNAVAILABLE;
        }
        if (meterRegistry != null) {
            meterRegistry.counter("sso.password.breach_check",
                    "outcome", result.name().toLowerCase()).increment();
        }
        return result;
    }

    /**
     * Range bodies are {@code SUFFIX:COUNT} per line. Padding entries carry a
     * count of zero and are decoys, not breaches.
     */
    static boolean containsSuffix(String body, String suffix) {
        if (body == null) throw new IllegalStateException("empty range response");
        for (String line : body.split("\r?\n")) {
            int colon = line.indexOf(':');
            if (colon < 0) continue;
            if (!line.substring(0, colon).trim().equalsIgnoreCase(suffix)) continue;
            try {
                return Long.parseLong(line.substring(colon + 1).trim()) > 0;
            } catch (NumberFormatException e) {
                return true; // a matching suffix with an unreadable count is still a match
            }
        }
        return false;
    }

    static String sha1Hex(String password) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-1")
                    .digest(password.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().withUpperCase().formatHex(digest);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-1 not available", e);
        }
    }

    private static Function<String, String> httpFetcher(String rangeUrl, Duration timeout) {
        HttpClient client = HttpClient.newBuilder()
                .connectTimeout(timeout)
                .followRedirects(HttpClient.Redirect.NEVER)
                .build();
        return prefix -> {
            // Validated per call, not at boot: DNS may be unavailable when the
            // pod starts, and a refused URL must fail open like any outage.
            URI uri = EgressGuard.validate(rangeUrl + prefix);
            HttpRequest request = HttpRequest.newBuilder(uri)
                    .timeout(timeout)
                    .header("Add-Padding", "true")
                    .header("User-Agent", "WeldForge-IdP")
                    .GET()
                    .build();
            try {
                HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
                if (response.statusCode() != 200) {
                    throw new IllegalStateException("range API returned HTTP " + response.statusCode());
                }
                return response.body();
            } catch (java.io.IOException e) {
                throw new IllegalStateException("range API unreachable: " + e.getMessage(), e);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IllegalStateException("interrupted", e);
            }
        };
    }
}
