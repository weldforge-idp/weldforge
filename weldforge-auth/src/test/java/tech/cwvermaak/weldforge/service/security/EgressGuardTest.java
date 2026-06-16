package tech.cwvermaak.weldforge.service.security;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * SSRF egress guard spec (B-LEGACY-1). Uses literal IPs so the tests are
 * hermetic (no DNS), with comprehensive positive and negative coverage of the
 * blocked ranges and scheme/host rules.
 */
class EgressGuardTest {

    // ---- positive: public, http(s) targets are allowed ----------------

    @ParameterizedTest
    @ValueSource(strings = {
            "https://1.1.1.1/webhook",
            "http://8.8.8.8:8080/hook",
            "https://93.184.216.34/path?x=1"   // public literal
    })
    @DisplayName("allows http/https URLs to public addresses")
    void allowsPublic(String url) {
        assertThatCode(() -> EgressGuard.validate(url)).doesNotThrowAnyException();
    }

    // ---- negative: internal / metadata ranges are blocked -------------

    @ParameterizedTest
    @ValueSource(strings = {
            "http://169.254.169.254/latest/meta-data/",  // cloud metadata (link-local)
            "http://127.0.0.1/",                          // loopback
            "https://127.0.0.1:9000/admin",
            "http://localhost/",                          // resolves to loopback
            "http://10.0.0.5/",                           // RFC1918
            "http://172.16.0.9/",                         // RFC1918
            "http://192.168.1.1/",                        // RFC1918
            "http://0.0.0.0/",                            // any-local
            "http://100.64.0.1/",                         // CGNAT
            "http://[::1]/",                              // IPv6 loopback
            "http://[fd00::1]/"                           // IPv6 unique-local
    })
    @DisplayName("blocks loopback, link-local/metadata, RFC1918, CGNAT and ULA")
    void blocksInternal(String url) {
        assertThatThrownBy(() -> EgressGuard.validate(url))
                .isInstanceOf(EgressNotAllowedException.class);
    }

    // ---- negative: scheme / host rules --------------------------------

    @ParameterizedTest
    @ValueSource(strings = {
            "file:///etc/passwd",
            "ftp://1.1.1.1/x",
            "gopher://1.1.1.1/",
            "ldap://1.1.1.1/"
    })
    @DisplayName("blocks non-http(s) schemes")
    void blocksScheme(String url) {
        assertThatThrownBy(() -> EgressGuard.validate(url))
                .isInstanceOf(EgressNotAllowedException.class)
                .hasMessageContaining("http");
    }

    @Test
    @DisplayName("rejects blank, null and host-less URLs")
    void rejectsMalformed() {
        assertThatThrownBy(() -> EgressGuard.validate(null)).isInstanceOf(EgressNotAllowedException.class);
        assertThatThrownBy(() -> EgressGuard.validate("   ")).isInstanceOf(EgressNotAllowedException.class);
        assertThatThrownBy(() -> EgressGuard.validate("https:///nohost")).isInstanceOf(EgressNotAllowedException.class);
        assertThatThrownBy(() -> EgressGuard.validate("not a url")).isInstanceOf(EgressNotAllowedException.class);
    }
}
