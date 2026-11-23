package tech.cwvermaak.weldforge.service.saml;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * WF-12 — the SAML metadata URL import passes the SSRF egress guard before it
 * fetches, so it cannot be used to reach loopback, RFC-1918 or the
 * 169.254.169.254 cloud-metadata endpoint. The guard rejects these before any
 * socket is opened, so these assertions make no network call.
 */
class SamlMetadataParserEgressTest {

    private final SamlMetadataParser parser = new SamlMetadataParser();

    @Test
    @DisplayName("the cloud-metadata endpoint is refused")
    void refusesCloudMetadata() {
        assertThatThrownBy(() -> parser.importFromUrl("http://169.254.169.254/latest/meta-data/"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("rejected");
    }

    @Test
    @DisplayName("loopback is refused")
    void refusesLoopback() {
        assertThatThrownBy(() -> parser.importFromUrl("http://127.0.0.1:8076/actuator/env"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("rejected");
    }

    @Test
    @DisplayName("an RFC-1918 private address is refused")
    void refusesPrivateRange() {
        assertThatThrownBy(() -> parser.importFromUrl("http://10.0.0.5/metadata"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("rejected");
    }

    @Test
    @DisplayName("a non-http scheme is refused")
    void refusesNonHttpScheme() {
        assertThatThrownBy(() -> parser.importFromUrl("file:///etc/passwd"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("rejected");
    }

    @Test
    @DisplayName("a blank URL is the existing required-field error, not an egress refusal")
    void blankIsRequiredField() {
        assertThatThrownBy(() -> parser.importFromUrl("  "))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("required");
    }
}
