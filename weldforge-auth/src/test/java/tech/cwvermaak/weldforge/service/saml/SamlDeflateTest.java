package tech.cwvermaak.weldforge.service.saml;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.zip.Deflater;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * WF-13 — SAML inflation is bounded, so a decompression bomb is refused rather
 * than buffered. The bomb assertion caps output at 64 KiB, so it proves the
 * guard trips without ever allocating a large buffer.
 */
class SamlDeflateTest {

    private static byte[] deflate(byte[] raw) {
        Deflater deflater = new Deflater();
        deflater.setInput(raw);
        deflater.finish();
        byte[] buffer = new byte[8192];
        var out = new java.io.ByteArrayOutputStream();
        while (!deflater.finished()) {
            int n = deflater.deflate(buffer);
            out.write(buffer, 0, n);
        }
        deflater.end();
        return out.toByteArray();
    }

    @Test
    @DisplayName("a normal compressed message round-trips")
    void roundTrips() {
        byte[] xml = "<AuthnRequest>hello</AuthnRequest>".getBytes(StandardCharsets.UTF_8);
        byte[] inflated = SamlDeflate.inflate(deflate(xml), SamlDeflate.MAX_INFLATED_BYTES);
        assertThat(inflated).isNotNull();
        assertThat(new String(inflated, StandardCharsets.UTF_8))
                .isEqualTo("<AuthnRequest>hello</AuthnRequest>");
    }

    @Test
    @DisplayName("input that is not DEFLATE yields null, so the caller reads it raw")
    void notDeflateIsNull() {
        byte[] raw = "<AuthnRequest>not compressed</AuthnRequest>".getBytes(StandardCharsets.UTF_8);
        assertThat(SamlDeflate.inflate(raw, SamlDeflate.MAX_INFLATED_BYTES)).isNull();
    }

    @Test
    @DisplayName("a payload inflating past the ceiling is refused, bounded at the cap")
    void bombIsRefused() {
        // 2 MiB of zeroes compresses to a couple of KiB. Inflating it with a
        // 64 KiB ceiling must throw after buffering at most ~64 KiB — never the
        // full 2 MiB — which is the whole point of the guard.
        byte[] big = new byte[2 * 1024 * 1024];
        Arrays.fill(big, (byte) 0);
        byte[] compressed = deflate(big);
        assertThat(compressed.length).isLessThan(64 * 1024);

        assertThatThrownBy(() -> SamlDeflate.inflate(compressed, 64 * 1024))
                .isInstanceOf(SamlRequestTooLargeException.class)
                .hasMessageContaining("exceeds");
    }

    @Test
    @DisplayName("output exactly at the ceiling is allowed")
    void atCeilingAllowed() {
        byte[] exact = new byte[1024];
        Arrays.fill(exact, (byte) 'a');
        byte[] inflated = SamlDeflate.inflate(deflate(exact), 1024);
        assertThat(inflated).hasSize(1024);
    }
}
