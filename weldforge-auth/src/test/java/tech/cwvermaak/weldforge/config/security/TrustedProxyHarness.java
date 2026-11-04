package tech.cwvermaak.weldforge.config.security;

import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.catalina.valves.RemoteIpValve;
import org.springframework.boot.env.YamlPropertySourceLoader;
import org.springframework.boot.web.embedded.tomcat.TomcatServletWebServerFactory;
import org.springframework.boot.web.server.WebServer;
import org.springframework.core.env.PropertySource;
import org.springframework.core.env.StandardEnvironment;
import org.springframework.core.io.ClassPathResource;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.List;

/**
 * A real Tomcat with a real {@link RemoteIpValve}, configured from the shipped
 * {@code application.yml}, for proving what the application sees as the client
 * address (B-AUTH-1).
 *
 * <p>This exists because the trusted-proxy boundary is <em>connector</em>
 * configuration. MockMvc never runs a valve and a mocked
 * {@code HttpServletRequest} returns whatever it was told to, so the entire
 * test suite could pass with the boundary wide open and every rate-limit
 * bucket, lockout counter and audit IP chosen by the caller. Only a real
 * connector can answer the question.
 *
 * <p>The regex is read from {@code application.yml} and resolved the way Spring
 * resolves it, so these tests pin the value that actually deploys rather than a
 * copy of it that can drift.
 *
 * <p><strong>Close it.</strong> Tomcat's acceptor and poller threads are not
 * daemons, so a harness left running holds the surefire fork open until
 * {@code forkedProcessExitTimeoutInSeconds} (180, set in the pom for exactly
 * this class of problem) expires and the fork is killed — three silent minutes
 * added to every CI run, reported as nothing at all. Hence
 * {@link AutoCloseable} and an owner on each side: {@code @AfterAll} in the
 * JUnit test, Cucumber's {@code @AfterAll} in the step definitions.
 */
public final class TrustedProxyHarness implements AutoCloseable {

    /** A public address standing in for an attacker-supplied value. */
    public static final String SPOOFED = "203.0.113.77";
    /** A second one, for a longer forged prefix. */
    public static final String ALSO_SPOOFED = "203.0.113.78";
    /** A public address standing in for the real client. */
    public static final String REAL_CLIENT = "198.51.100.9";
    /** Traefik's pod on this cluster; the pod CIDR is 10.42.0.0/24. */
    public static final String PROXY_HOP = "10.42.0.22";

    private final String internalProxies;
    private final WebServer server;
    private final String echoUrl;
    private final HttpClient http;

    private TrustedProxyHarness() {
        this.internalProxies = configured("server.tomcat.remoteip.internal-proxies");

        RemoteIpValve valve = new RemoteIpValve();
        valve.setInternalProxies(internalProxies);
        valve.setRemoteIpHeader(configured("server.tomcat.remoteip.remote-ip-header"));
        valve.setProtocolHeader(configured("server.tomcat.remoteip.protocol-header"));

        TomcatServletWebServerFactory factory = new TomcatServletWebServerFactory(0);
        factory.addEngineValves(valve);
        this.server = factory.getWebServer(context ->
                context.addServlet("echo", new HttpServlet() {
                    @Override
                    protected void service(HttpServletRequest request, HttpServletResponse response)
                            throws IOException {
                        response.setContentType("text/plain");
                        // Exactly what the production call sites read.
                        response.getWriter().write(request.getRemoteAddr() + "|" + request.getScheme());
                    }
                }).addMapping("/echo"));
        this.server.start();
        this.echoUrl = "http://127.0.0.1:" + server.getPort() + "/echo";
        this.http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();
    }

    /** Start a harness. The caller owns it and must {@link #close()} it. */
    public static TrustedProxyHarness start() {
        return new TrustedProxyHarness();
    }

    @Override
    public void close() {
        try {
            http.close();
        } finally {
            server.stop();
        }
    }

    /** Read a property from the shipped application.yml, resolving placeholders as Spring would. */
    private static String configured(String key) {
        StandardEnvironment env = new StandardEnvironment();
        try {
            List<PropertySource<?>> sources = new YamlPropertySourceLoader()
                    .load("application", new ClassPathResource("application.yml"));
            for (PropertySource<?> source : sources) {
                env.getPropertySources().addLast(source);
            }
        } catch (IOException e) {
            throw new IllegalStateException("application.yml is not readable from the test classpath", e);
        }
        String value = env.getProperty(key);
        if (value == null || value.isBlank()) {
            throw new IllegalStateException(key + " must be set in application.yml");
        }
        return value;
    }

    /** The trusted-proxy regex this application deploys with. */
    public String internalProxies() {
        return internalProxies;
    }

    /** The address the application would see, given these forwarded headers (name, value, …). */
    public String remoteAddrSeenBy(String... headers) {
        return echo(headers)[0];
    }

    /** The scheme the application would see, given these forwarded headers. */
    public String schemeSeenBy(String... headers) {
        return echo(headers)[1];
    }

    private String[] echo(String... headers) {
        HttpRequest.Builder request = HttpRequest.newBuilder(URI.create(echoUrl))
                .timeout(Duration.ofSeconds(10))
                .GET();
        for (int i = 0; i < headers.length; i += 2) {
            request.header(headers[i], headers[i + 1]);
        }
        try {
            HttpResponse<String> response = http.send(request.build(), HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() != 200) {
                throw new IllegalStateException("echo servlet answered " + response.statusCode());
            }
            return response.body().split("\\|", -1);
        } catch (IOException e) {
            throw new IllegalStateException("echo request failed", e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("echo request interrupted", e);
        }
    }
}
