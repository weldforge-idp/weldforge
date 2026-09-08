package tech.cwvermaak.weldforge.service.oidc;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("RedirectUriMatcher — exact match, plus RFC 8252 §7.3 loopback ports")
class RedirectUriMatcherTest {

    private static final List<String> LOOPBACK = List.of("http://127.0.0.1/callback");

    @Nested
    @DisplayName("exact matching (the rule for everything that is not loopback)")
    class Exact {

        @Test
        @DisplayName("a registered https URI matches itself")
        void matchesItself() {
            assertThat(RedirectUriMatcher.matches(
                    List.of("https://app.example/login/oauth2/code/weldforge"),
                    "https://app.example/login/oauth2/code/weldforge")).isTrue();
        }

        @Test
        @DisplayName("a different path on a registered host does not match")
        void differentPath() {
            assertThat(RedirectUriMatcher.matches(
                    List.of("https://app.example/callback"),
                    "https://app.example/elsewhere")).isFalse();
        }

        @Test
        @DisplayName("a different port on a registered https URI does not match")
        void httpsPortIsNotIgnored() {
            assertThat(RedirectUriMatcher.matches(
                    List.of("https://app.example:8443/callback"),
                    "https://app.example:9443/callback")).isFalse();
        }

        @Test
        @DisplayName("the first of several registered URIs is not privileged")
        void matchesAnyRegisteredEntry() {
            List<String> registered = List.of(
                    "https://app.example/a", "https://app.example/b", "https://app.example/c");
            assertThat(RedirectUriMatcher.matches(registered, "https://app.example/c")).isTrue();
        }

        @Test
        @DisplayName("an empty registration matches nothing")
        void emptyRegistration() {
            assertThat(RedirectUriMatcher.matches(List.of(), "https://app.example/cb")).isFalse();
        }

        @Test
        @DisplayName("null and blank inputs are refused rather than throwing")
        void nullsAndBlanks() {
            assertThat(RedirectUriMatcher.matches(null, "https://app.example/cb")).isFalse();
            assertThat(RedirectUriMatcher.matches(LOOPBACK, null)).isFalse();
            assertThat(RedirectUriMatcher.matches(LOOPBACK, "  ")).isFalse();
        }
    }

    @Nested
    @DisplayName("loopback: the port is ignored so a native app can use an ephemeral one")
    class LoopbackPorts {

        @ParameterizedTest(name = "registered http://127.0.0.1/callback matches {0}")
        @ValueSource(strings = {
                "http://127.0.0.1:47821/callback",
                "http://127.0.0.1:1/callback",
                "http://127.0.0.1:65535/callback",
                "http://127.0.0.1/callback",
        })
        @DisplayName("any port on the registered path is accepted")
        void anyPort(String requested) {
            assertThat(RedirectUriMatcher.matches(LOOPBACK, requested)).isTrue();
        }

        @Test
        @DisplayName("a registered URI that carries a port still matches a different one")
        void registeredPortIsAlsoIgnored() {
            assertThat(RedirectUriMatcher.matches(
                    List.of("http://127.0.0.1:8080/callback"),
                    "http://127.0.0.1:47821/callback")).isTrue();
        }

        @Test
        @DisplayName("IPv6 loopback works the same way")
        void ipv6Loopback() {
            assertThat(RedirectUriMatcher.matches(
                    List.of("http://[::1]/callback"),
                    "http://[::1]:47821/callback")).isTrue();
        }

        @Test
        @DisplayName("IPv4 and IPv6 loopback are different hosts, not interchangeable")
        void v4DoesNotMatchV6() {
            assertThat(RedirectUriMatcher.matches(LOOPBACK, "http://[::1]:47821/callback")).isFalse();
            assertThat(RedirectUriMatcher.matches(
                    List.of("http://[::1]/callback"),
                    "http://127.0.0.1:47821/callback")).isFalse();
        }

        @Test
        @DisplayName("the path still has to match")
        void pathStillMatters() {
            assertThat(RedirectUriMatcher.matches(LOOPBACK, "http://127.0.0.1:47821/other")).isFalse();
        }

        @Test
        @DisplayName("a traversal segment is not normalised away")
        void pathTraversalDoesNotMatch() {
            assertThat(RedirectUriMatcher.matches(
                    List.of("http://127.0.0.1/callback"),
                    "http://127.0.0.1:47821/callback/../evil")).isFalse();
        }

        @Test
        @DisplayName("the query string still has to match")
        void queryStillMatters() {
            assertThat(RedirectUriMatcher.matches(
                    List.of("http://127.0.0.1/callback?app=desktop"),
                    "http://127.0.0.1:47821/callback?app=web")).isFalse();
            assertThat(RedirectUriMatcher.matches(
                    List.of("http://127.0.0.1/callback?app=desktop"),
                    "http://127.0.0.1:47821/callback?app=desktop")).isTrue();
        }
    }

    @Nested
    @DisplayName("the exception stays narrow — everything else keeps exact matching")
    class NarrowException {

        @Test
        @DisplayName("localhost is NOT port-agnostic: the name can resolve off-machine (RFC 8252 §8.3)")
        void localhostIsNotLoopbackForThisPurpose() {
            assertThat(RedirectUriMatcher.matches(
                    List.of("http://localhost/callback"),
                    "http://localhost:47821/callback")).isFalse();
        }

        @Test
        @DisplayName("a registered localhost URI still matches itself exactly")
        void localhostStillWorksExactly() {
            assertThat(RedirectUriMatcher.matches(
                    List.of("http://localhost:5173/callback"),
                    "http://localhost:5173/callback")).isTrue();
        }

        @Test
        @DisplayName("a neighbouring 127.x address is a different host")
        void otherLoopbackRangeAddress() {
            assertThat(RedirectUriMatcher.matches(LOOPBACK, "http://127.0.0.2:47821/callback")).isFalse();
        }

        @Test
        @DisplayName("a public address never borrows the loopback rule")
        void publicHostIsNotRelaxed() {
            assertThat(RedirectUriMatcher.matches(
                    List.of("http://127.0.0.1/callback"),
                    "http://evil.example:47821/callback")).isFalse();
            assertThat(RedirectUriMatcher.matches(
                    List.of("https://app.example/callback"),
                    "https://app.example:8443/callback")).isFalse();
        }

        @Test
        @DisplayName("https loopback is compared exactly — the RFC scopes the rule to http")
        void httpsLoopbackIsExact() {
            assertThat(RedirectUriMatcher.matches(
                    List.of("https://127.0.0.1/callback"),
                    "https://127.0.0.1:47821/callback")).isFalse();
        }

        @Test
        @DisplayName("userinfo is refused rather than parsed as a loopback host")
        void userInfoIsRefused() {
            assertThat(RedirectUriMatcher.matches(
                    List.of("http://127.0.0.1/callback"),
                    "http://evil@127.0.0.1:47821/callback")).isFalse();
        }

        @Test
        @DisplayName("a fragment is refused — RFC 6749 §3.1.2 forbids one on a redirect URI")
        void fragmentIsRefused() {
            assertThat(RedirectUriMatcher.matches(
                    List.of("http://127.0.0.1/callback"),
                    "http://127.0.0.1:47821/callback#x")).isFalse();
        }

        @Test
        @DisplayName("a malformed URI is refused rather than throwing")
        void malformedUri() {
            assertThat(RedirectUriMatcher.matches(LOOPBACK, "http://127.0.0.1:notaport/callback")).isFalse();
            assertThat(RedirectUriMatcher.matches(LOOPBACK, "::::")).isFalse();
        }

        @Test
        @DisplayName("a registered entry that is unparseable does not break the others")
        void unparseableRegisteredEntryIsSkipped() {
            assertThat(RedirectUriMatcher.matches(
                    List.of("h ttp://broken", "http://127.0.0.1/callback"),
                    "http://127.0.0.1:47821/callback")).isTrue();
        }
    }
}
