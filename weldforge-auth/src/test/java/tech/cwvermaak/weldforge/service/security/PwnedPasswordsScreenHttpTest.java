package tech.cwvermaak.weldforge.service.security;

import com.sun.net.httpserver.HttpServer;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The breach screen over real HTTP (CONF-7.1), against a loopback server that
 * records every request. {@link PwnedPasswordsScreenTest} covers the matching
 * logic; this covers what actually goes on the wire, and the failure modes of
 * the transport itself -- each of which must fail open.
 *
 * <p>The egress guard is replaced by a permissive one here, because the real
 * guard correctly refuses loopback; {@code PwnedPasswordsScreenTest} proves the
 * real guard is applied.
 */
class PwnedPasswordsScreenHttpTest {

    // SHA-1("password") = 5BAA6 1E4C9B93F3F0682250B6CF8331B7EE68FD8
    private static final String PASSWORD = "password";
    private static final String SUFFIX = "1E4C9B93F3F0682250B6CF8331B7EE68FD8";

    private HttpServer server;
    private final List<String> paths = new CopyOnWriteArrayList<>();
    private final List<String> queries = new CopyOnWriteArrayList<>();
    private final List<String> paddingHeaders = new CopyOnWriteArrayList<>();
    private final List<String> userAgents = new CopyOnWriteArrayList<>();
    private final List<String> methods = new CopyOnWriteArrayList<>();
    private final List<Integer> requestBodyLengths = new CopyOnWriteArrayList<>();

    private volatile int status = 200;
    private volatile String body = "";
    private volatile String location;
    private volatile long delayMs;

    @BeforeEach
    void start() throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> {
            paths.add(exchange.getRequestURI().getPath());
            queries.add(String.valueOf(exchange.getRequestURI().getQuery()));
            paddingHeaders.add(exchange.getRequestHeaders().getFirst("Add-Padding"));
            userAgents.add(exchange.getRequestHeaders().getFirst("User-Agent"));
            methods.add(exchange.getRequestMethod());
            requestBodyLengths.add(exchange.getRequestBody().readAllBytes().length);
            try {
                if (delayMs > 0) Thread.sleep(delayMs);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            if (location != null) exchange.getResponseHeaders().add("Location", location);
            byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(status, bytes.length == 0 ? -1 : bytes.length);
            if (bytes.length > 0) {
                try (OutputStream out = exchange.getResponseBody()) {
                    out.write(bytes);
                }
            }
            exchange.close();
        });
        server.start();
    }

    @AfterEach
    void stop() {
        server.stop(0);
    }

    private String rangeUrl() {
        return "http://127.0.0.1:" + server.getAddress().getPort() + "/range/";
    }

    private PwnedPasswordsScreen screen(Duration timeout) {
        return new PwnedPasswordsScreen(rangeUrl(),
                PwnedPasswordsScreen.httpFetcher(rangeUrl(), timeout, URI::create),
                new SimpleMeterRegistry());
    }

    @Test
    @DisplayName("On the wire: one GET for /range/{5-char prefix}, no body, no query, no password")
    void wire_carries_only_the_prefix() {
        body = SUFFIX + ":42\r\n";

        screen(Duration.ofSeconds(2)).check(PASSWORD);

        assertThat(methods).containsExactly("GET");
        assertThat(paths).containsExactly("/range/5BAA6");
        assertThat(queries).containsExactly("null");
        assertThat(requestBodyLengths).containsExactly(0);
        String everythingSent = paths + " " + queries + " " + paddingHeaders + " " + userAgents;
        assertThat(everythingSent)
                .doesNotContain(PASSWORD)
                .doesNotContain(SUFFIX)
                .doesNotContain(PwnedPasswordsScreen.sha1Hex(PASSWORD));
    }

    @Test
    @DisplayName("Asks for padding, so the response size does not narrow the prefix down")
    void requests_padding_and_identifies_itself() {
        screen(Duration.ofSeconds(2)).check(PASSWORD);

        assertThat(paddingHeaders).containsExactly("true");
        assertThat(userAgents).containsExactly("WeldForge-IdP");
    }

    @Test
    @DisplayName("A 200 range containing the suffix is a breach")
    void breach_over_http() {
        body = "0018A45C4D1DEF81644B54AB7F969B88D65:3\r\n" + SUFFIX + ":9545824\r\n";

        assertThat(screen(Duration.ofSeconds(2)).check(PASSWORD))
                .isEqualTo(BreachedPasswordScreen.Result.BREACHED);
    }

    @Test
    @DisplayName("A non-200 answer fails open")
    void non_200_fails_open() {
        status = 503;
        body = "down for maintenance";

        assertThat(screen(Duration.ofSeconds(2)).check(PASSWORD))
                .isEqualTo(BreachedPasswordScreen.Result.UNAVAILABLE);
    }

    @Test
    @DisplayName("A redirect is not followed -- it could lead anywhere the egress guard never saw")
    void redirect_not_followed() {
        status = 302;
        location = "http://169.254.169.254/latest/meta-data/";

        assertThat(screen(Duration.ofSeconds(2)).check(PASSWORD))
                .isEqualTo(BreachedPasswordScreen.Result.UNAVAILABLE);
        assertThat(paths).hasSize(1);
    }

    @Test
    @DisplayName("A slow corpus times out and fails open, rather than holding registration hostage")
    void timeout_fails_open() {
        delayMs = 1_500;
        long started = System.nanoTime();

        BreachedPasswordScreen.Result result = screen(Duration.ofMillis(250)).check(PASSWORD);

        assertThat(result).isEqualTo(BreachedPasswordScreen.Result.UNAVAILABLE);
        assertThat(Duration.ofNanos(System.nanoTime() - started)).isLessThan(Duration.ofMillis(1_400));
    }

    @Test
    @DisplayName("An unreachable corpus fails open")
    void unreachable_fails_open() {
        server.stop(0);

        assertThat(screen(Duration.ofMillis(500)).check(PASSWORD))
                .isEqualTo(BreachedPasswordScreen.Result.UNAVAILABLE);
    }
}
