package tech.cwvermaak.weldforge.config.security;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static tech.cwvermaak.weldforge.config.security.TrustedProxyHarness.ALSO_SPOOFED;
import static tech.cwvermaak.weldforge.config.security.TrustedProxyHarness.PROXY_HOP;
import static tech.cwvermaak.weldforge.config.security.TrustedProxyHarness.REAL_CLIENT;
import static tech.cwvermaak.weldforge.config.security.TrustedProxyHarness.SPOOFED;

/**
 * The trusted-proxy boundary that decides whether {@code getRemoteAddr()} can
 * be believed (B-AUTH-1).
 *
 * <p>Rate limiting, account lockout, the audit trail and refresh-token
 * provenance all key on that one value, and all four read it through
 * {@code HttpServletRequest.getRemoteAddr()} rather than parsing a header. That
 * is only worth anything while {@code server.tomcat.remoteip.internal-proxies}
 * names a narrow boundary, because {@code RemoteIpValve} walks
 * {@code X-Forwarded-For} right-to-left and stops at the first entry that is
 * <em>not</em> a trusted proxy. The property was {@code ".*"}: every entry
 * matched, the walk consumed the whole chain, and the valve returned the
 * <em>leftmost</em> entry — the one value a client sets freely. Reading
 * {@code getRemoteAddr()} and parsing the raw header's leftmost token were
 * therefore the same thing, and the earlier fix that switched between them
 * fixed nothing.
 *
 * <p>See {@link TrustedProxyHarness} for why this needs a real connector.
 */
@DisplayName("Trusted-proxy boundary (B-AUTH-1)")
class TrustedProxyBoundaryTest {

    private static TrustedProxyHarness app;

    @BeforeAll
    static void startTomcatWithTheProductionValve() {
        app = TrustedProxyHarness.start();
    }

    @AfterAll
    static void stop() {
        // Not optional: Tomcat's threads are not daemons, so leaving it running
        // holds the surefire fork open for the full 180s exit timeout.
        if (app != null) {
            app.close();
        }
    }

    // ---- the regression -------------------------------------------------

    @Test
    @DisplayName("THE POINT: a forged prefix is ignored; the rightmost non-proxy entry wins")
    void forgedPrefixIsIgnored() {
        // The shape that arrives when the edge trusts an inbound chain and
        // appends the real peer: the client's own value is on the LEFT. Under
        // the old `.*` boundary the valve returned SPOOFED here, handing an
        // attacker a fresh rate-limit bucket on every request.
        assertThat(app.remoteAddrSeenBy("X-Forwarded-For", SPOOFED + ", " + REAL_CLIENT))
                .isEqualTo(REAL_CLIENT);
    }

    @Test
    @DisplayName("a longer forged prefix is ignored too")
    void longerForgedPrefixIsIgnored() {
        assertThat(app.remoteAddrSeenBy("X-Forwarded-For",
                SPOOFED + ", " + ALSO_SPOOFED + ", " + REAL_CLIENT))
                .isEqualTo(REAL_CLIENT);
    }

    @Test
    @DisplayName("a forged prefix behind a private hop is still ignored")
    void forgedPrefixBehindAPrivateHopIsIgnored() {
        // Internal hops are skipped, so the walk reaches past them to the
        // rightmost public entry, not to the leftmost forged one.
        assertThat(app.remoteAddrSeenBy("X-Forwarded-For",
                SPOOFED + ", " + REAL_CLIENT + ", " + PROXY_HOP))
                .isEqualTo(REAL_CLIENT);
    }

    // ---- what must keep working ----------------------------------------

    @Test
    @DisplayName("the production shape: one entry set by the edge is the client")
    void singleEntryFromTheEdgeIsHonoured() {
        // Traefik strips an inbound X-Forwarded-For from an untrusted peer and
        // sets this itself, so this is the chain the pod normally receives.
        assertThat(app.remoteAddrSeenBy("X-Forwarded-For", REAL_CLIENT)).isEqualTo(REAL_CLIENT);
    }

    @Test
    @DisplayName("no forwarded header at all falls back to the peer")
    void noHeaderFallsBackToThePeer() {
        assertThat(app.remoteAddrSeenBy()).isEqualTo("127.0.0.1");
    }

    @Test
    @DisplayName("a chain of only private hops does not throw")
    void chainOfOnlyPrivateHops() {
        assertThat(app.remoteAddrSeenBy("X-Forwarded-For", PROXY_HOP + ", 10.42.0.31")).isNotBlank();
    }

    @Test
    @DisplayName("the scheme is still rewritten, so the OIDC issuer does not regress to http")
    void schemeIsStillRewritten() {
        // The one way narrowing the boundary can bite: if it stopped matching
        // the real peer the valve would stop rewriting, request.getScheme()
        // would revert to http, and the issuer, authorize/token endpoints and
        // the discovery document would advertise http://<pod>.
        assertThat(app.schemeSeenBy("X-Forwarded-Proto", "https")).isEqualTo("https");
        assertThat(app.schemeSeenBy()).isEqualTo("http");
    }

    // ---- the boundary itself -------------------------------------------

    @Nested
    @DisplayName("the configured boundary")
    class TheBoundary {

        @Test
        @DisplayName("is not a wildcard — widening it back silently disables rate limiting")
        void isNotAWildcard() {
            // Executable form of the rule in application.yml's comment. `.*`
            // reads like "we sit behind a proxy" and means "every client may
            // choose its own rate-limit bucket, audit IP and session IP".
            assertThat(app.internalProxies())
                    .as("server.tomcat.remoteip.internal-proxies")
                    .isNotEqualTo(".*")
                    .isNotEqualTo(".+")
                    .doesNotContain("${");
        }

        @Test
        @DisplayName("trusts the cluster's proxy hop")
        void trustsTheProxyHop() {
            Pattern boundary = Pattern.compile(app.internalProxies());
            assertThat(boundary.matcher(PROXY_HOP).matches()).isTrue();
            assertThat(boundary.matcher("127.0.0.1").matches()).isTrue();
        }

        @Test
        @DisplayName("does not trust a public address")
        void doesNotTrustPublicAddresses() {
            Pattern boundary = Pattern.compile(app.internalProxies());
            for (String publicAddress : new String[]{SPOOFED, REAL_CLIENT, "8.8.8.8", "196.40.100.82"}) {
                assertThat(boundary.matcher(publicAddress).matches())
                        .as("%s must not count as a trusted proxy", publicAddress)
                        .isFalse();
            }
        }
    }

    // ---- the rule the four call sites depend on -------------------------

    @Test
    @DisplayName("no production code reads X-Forwarded-For directly")
    void noProductionCodeReadsTheHeaderDirectly() throws IOException {
        // The boundary is worth nothing if a call site goes back to parsing the
        // header itself, which is what B-AUTH-1 originally found. Enforcing it
        // here covers all four call sites — RateLimitingFilter, AuditService,
        // AuthService and OidcAuthorizationController — and any added later.
        Path main = Path.of("src/main/java");
        try (Stream<Path> files = Files.walk(main)) {
            List<String> offenders = files
                    .filter(p -> p.toString().endsWith(".java"))
                    .filter(p -> {
                        try {
                            String body = Files.readString(p);
                            // A comment mentioning the header is the point; a
                            // getHeader call on it is the defect.
                            return body.contains("getHeader(\"X-Forwarded-For\")")
                                    || body.contains("getHeaders(\"X-Forwarded-For\")")
                                    || body.contains("getHeader(\"x-forwarded-for\")");
                        } catch (IOException e) {
                            throw new IllegalStateException(p.toString(), e);
                        }
                    })
                    .map(p -> p.getFileName().toString())
                    .toList();
            assertThat(offenders)
                    .as("read the valve-resolved getRemoteAddr() instead; see application.yml's "
                        + "internal-proxies comment")
                    .isEmpty();
        }
    }
}
