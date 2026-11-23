package tech.cwvermaak.weldforge.service.oidc;

import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import tech.cwvermaak.weldforge.model.OidcClient;
import tech.cwvermaak.weldforge.model.Tenant;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * B-OIDC-7 — a presented client secret is checked against the stored hash, or,
 * for a client that predates the migration and has not rotated, against the
 * legacy encrypted form, which is metered so stragglers are visible.
 */
class ClientSecretVerifierTest {

    private SimpleMeterRegistry meterRegistry;
    private ClientSecretVerifier verifier;
    private Tenant tenant;

    @BeforeEach
    void setUp() {
        meterRegistry = new SimpleMeterRegistry();
        verifier = new ClientSecretVerifier(meterRegistry);
        tenant = Tenant.builder().id(1L).slug("acme").name("Acme").build();
    }

    private OidcClient hashed(String secret) {
        return OidcClient.builder().id(10L).tenant(tenant).clientId("acme-app")
                .clientSecretHash(OidcClientService.hashClientSecret(secret))
                .build();
    }

    private OidcClient legacy(String secret) {
        // No hash: the plaintext field stands in for the decrypted legacy value
        // (EncryptedStringConverter is a no-op on an in-memory builder).
        return OidcClient.builder().id(11L).tenant(tenant).clientId("old-app")
                .clientSecret(secret)
                .build();
    }

    private double legacyVerifyCount() {
        return meterRegistry.find("sso.oidc.client_secret.legacy_verify").counters()
                .stream().mapToDouble(c -> c.count()).sum();
    }

    @Test
    @DisplayName("a hashed client accepts the right secret and rejects a wrong one")
    void hashedPath() {
        OidcClient client = hashed("super-secret");
        assertThat(verifier.verify(client, "super-secret")).isTrue();
        assertThat(verifier.verify(client, "wrong")).isFalse();
        // The hashed path never touches the legacy meter.
        assertThat(legacyVerifyCount()).isZero();
    }

    @Test
    @DisplayName("a legacy (un-rotated) client still verifies, and a success is metered")
    void legacyPathMetered() {
        OidcClient client = legacy("old-secret");
        assertThat(verifier.verify(client, "old-secret")).isTrue();
        assertThat(legacyVerifyCount())
                .as("a successful legacy verify is counted so the operator can see the straggler")
                .isEqualTo(1.0);
    }

    @Test
    @DisplayName("a wrong secret on a legacy client fails and is not metered as a straggler")
    void legacyWrongNotMetered() {
        OidcClient client = legacy("old-secret");
        assertThat(verifier.verify(client, "nope")).isFalse();
        assertThat(legacyVerifyCount()).isZero();
    }

    @Test
    @DisplayName("a hash takes precedence over any legacy value and the hash decides")
    void hashWinsOverLegacy() {
        OidcClient client = OidcClient.builder().id(12L).tenant(tenant).clientId("both")
                .clientSecretHash(OidcClientService.hashClientSecret("current"))
                .clientSecret("stale-legacy")
                .build();
        assertThat(verifier.verify(client, "current")).isTrue();
        // The stale legacy value must not authenticate once a hash exists.
        assertThat(verifier.verify(client, "stale-legacy")).isFalse();
        assertThat(legacyVerifyCount()).isZero();
    }

    @Test
    @DisplayName("a client with neither hash nor secret (public, or misconfigured) never verifies")
    void noSecretNeverVerifies() {
        OidcClient client = OidcClient.builder().id(13L).tenant(tenant).clientId("pub")
                .publicClient(true).build();
        assertThat(verifier.verify(client, "anything")).isFalse();
        assertThat(verifier.verify(client, null)).isFalse();
    }

    @Test
    @DisplayName("a null presented secret or null client is false, never a match")
    void nullSafe() {
        assertThat(verifier.verify(hashed("s"), null)).isFalse();
        assertThat(verifier.verify(null, "s")).isFalse();
    }
}
