package tech.cwvermaak.weldforge.service.oidc;

import io.micrometer.core.instrument.MeterRegistry;
import org.springframework.stereotype.Component;
import tech.cwvermaak.weldforge.model.OidcClient;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

/**
 * The one place a presented {@code client_secret} is checked against a stored
 * one (B-OIDC-7). Every token-endpoint and introspection/revocation call site
 * routes through here so the hash-or-legacy decision lives once.
 *
 * <p>Two storage forms coexist during the migrate-on-rotation window:
 * <ul>
 *   <li>a client created or rotated after V75 carries only
 *       {@link OidcClient#getClientSecretHash()} — a SHA-256 of the secret, the
 *       same form the registration access token already uses — and is verified
 *       by hashing the presented value and comparing in constant time;</li>
 *   <li>a client that predates V75 and has not rotated still carries the
 *       reversibly-encrypted {@link OidcClient#getClientSecret()}, verified by a
 *       constant-time compare against the decrypted value. A successful verify
 *       on this path increments {@code sso.oidc.client_secret.legacy_verify}, so
 *       an operator can see which clients have not yet rotated onto a hash
 *       before the encrypted column is eventually retired.</li>
 * </ul>
 *
 * <p>A public client has neither and never authenticates with a secret, which
 * is the token endpoint's existing position (PKCE proves the caller instead);
 * this returns {@code false} for it, and callers that allow public clients test
 * {@link OidcClient#isPublicClient()} separately before asking.
 */
@Component
public class ClientSecretVerifier {

    private final MeterRegistry meterRegistry;

    public ClientSecretVerifier(MeterRegistry meterRegistry) {
        this.meterRegistry = meterRegistry;
    }

    /**
     * True when {@code presented} authenticates {@code client}. Constant-time on
     * the comparison; a null client, null secret, or a client holding no secret
     * at all (public) is {@code false}.
     */
    public boolean verify(OidcClient client, String presented) {
        if (client == null || presented == null) {
            return false;
        }
        String hash = client.getClientSecretHash();
        if (hash != null && !hash.isBlank()) {
            // Compare hashes, not the secret: hashing the presented value first
            // keeps a database dump from yielding anything usable.
            return constantTimeEquals(OidcClientService.hashClientSecret(presented), hash);
        }
        String legacy = client.getClientSecret();
        if (legacy == null) {
            // No hash and no encrypted secret: a public client, or a
            // misconfigured confidential one. Either way, nothing to match.
            return false;
        }
        boolean matched = constantTimeEquals(presented, legacy);
        if (matched) {
            meterRegistry.counter("sso.oidc.client_secret.legacy_verify",
                    "tenant", client.getTenant() != null ? client.getTenant().getSlug() : "unknown",
                    "client_id", client.getClientId() == null ? "unknown" : client.getClientId())
                    .increment();
        }
        return matched;
    }

    private static boolean constantTimeEquals(String a, String b) {
        if (a == null || b == null) return false;
        return MessageDigest.isEqual(
                a.getBytes(StandardCharsets.UTF_8),
                b.getBytes(StandardCharsets.UTF_8));
    }
}
