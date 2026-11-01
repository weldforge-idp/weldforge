package tech.cwvermaak.weldforge.config.security;

import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Set;

/**
 * Fails application startup fast when the security-critical secrets are
 * misconfigured, so a deployment can never silently fall back to a weak,
 * source-committed default.
 *
 * <p>Two layers of checks:
 * <ol>
 *   <li><b>Always</b> — every profile, including local dev — the secrets must
 *       meet a minimum length. {@code app.jwt.secret} is consumed as raw
 *       UTF-8 bytes by {@code Keys.hmacShaKeyFor}; HS512 needs 64 bytes, so
 *       anything shorter is a genuine misconfiguration anywhere.</li>
 *   <li><b>When {@code app.security.require-secure-secrets=true}</b> — set on
 *       every cluster deploy via the {@code APP_REQUIRE_SECURE_SECRETS} env in
 *       Helm values — the secrets must also not equal a known dev-only default.
 *       This is what turns a missing {@code JWT_SECRET}/{@code APP_CRYPTO_SECRET}
 *       env (which would otherwise fall through to the insecure
 *       {@code application.yml} default) into a hard boot failure in
 *       staging/production. Local runs leave the flag unset, so the convenient
 *       dev defaults keep working.</li>
 * </ol>
 *
 * The {@code app.jwt.secret} value is shared with external token consumers
 * (Safe Space / Krusty / Commons); see docs/runbooks/key-rotation.md for the
 * coordinated-rotation procedure.
 */
@Component
@Slf4j
public class SecretHygieneValidator {

    /** HS512 signing requires a 512-bit (64-byte) key. */
    private static final int MIN_JWT_SECRET_BYTES = 64;
    /** A passphrase shorter than this has too little entropy for at-rest encryption. */
    private static final int MIN_CRYPTO_SECRET_CHARS = 16;

    /**
     * Values that ship as defaults in application.yml. They exist only so a
     * fresh local checkout boots; they must never reach a real deployment.
     */
    private static final Set<String> KNOWN_INSECURE_DEFAULTS = Set.of(
            "dev-only-insecure-jwt-secret-do-not-use-in-production-change-me-now-0123456789",
            "dev-only-change-me-weldforge-tenant-secret-key",
            // Helm placeholder values — these are overridden by --set-string at
            // deploy time, so seeing them at runtime means the override was missed.
            "changeme-generate-a-256-bit-secret-key-here",
            "changeme-source-from-kms-or-hsm");

    @Value("${app.jwt.secret:}")
    private String jwtSecret;

    /**
     * Retired secrets still accepted for verification during a rotation overlap
     * (see {@link HmacKeyRing}). Held to exactly the same standard as the
     * signing key, because for the purpose that matters they are equally
     * powerful: anyone holding one can mint a token this server will accept. A
     * weak entry here would be a forgery oracle rather than untidiness.
     */
    @Value("${app.jwt.previous-secrets:}")
    private String jwtPreviousSecrets;

    @Value("${app.crypto.secret:}")
    private String cryptoSecret;

    @Value("${app.security.require-secure-secrets:false}")
    private boolean requireSecureSecrets;

    @PostConstruct
    void validate() {
        // --- Layer 1: length, enforced everywhere ---------------------
        int jwtBytes = jwtSecret == null ? 0 : jwtSecret.getBytes(StandardCharsets.UTF_8).length;
        if (jwtBytes < MIN_JWT_SECRET_BYTES) {
            throw new IllegalStateException(
                "app.jwt.secret must be at least " + MIN_JWT_SECRET_BYTES
                + " bytes (got " + jwtBytes + "). Set the JWT_SECRET env var to a strong random value.");
        }
        // Every retired key held for the overlap window, to the same floor.
        // This also catches the one mistake the comma-separated format invites:
        // a secret containing a comma is split into fragments, and every
        // fragment is far short of 64 bytes -- so a mis-split fails the boot
        // instead of leaving a server that trusts nonsense.
        List<String> previous = HmacKeyRing.parse(jwtPreviousSecrets);
        for (int i = 0; i < previous.size(); i++) {
            String value = previous.get(i);
            int bytes = value.getBytes(StandardCharsets.UTF_8).length;
            if (bytes < MIN_JWT_SECRET_BYTES) {
                throw new IllegalStateException(
                    "app.jwt.previous-secrets[" + i + "] must be at least " + MIN_JWT_SECRET_BYTES
                    + " bytes (got " + bytes + "). A verification key can mint tokens this server "
                    + "accepts, so it is held to the same standard as the signing key. If this list "
                    + "holds one secret that contains a comma, that is the cause: the value was split.");
            }
        }
        if (cryptoSecret == null || cryptoSecret.length() < MIN_CRYPTO_SECRET_CHARS) {
            throw new IllegalStateException(
                "app.crypto.secret must be at least " + MIN_CRYPTO_SECRET_CHARS
                + " characters. Set the APP_CRYPTO_SECRET env var to a strong random value.");
        }

        // --- Layer 2: reject known defaults on real deployments -------
        if (requireSecureSecrets) {
            if (KNOWN_INSECURE_DEFAULTS.contains(jwtSecret)) {
                throw new IllegalStateException(
                    "app.jwt.secret is a known insecure default but app.security.require-secure-secrets=true. "
                    + "The JWT_SECRET env var (GCP Secret Manager `wf-jwt-secret`) was not injected. Refusing to start.");
            }
            for (String value : HmacKeyRing.parse(jwtPreviousSecrets)) {
                if (KNOWN_INSECURE_DEFAULTS.contains(value)) {
                    throw new IllegalStateException(
                        "app.jwt.previous-secrets contains a known insecure default but "
                        + "app.security.require-secure-secrets=true. A retired key still verifies, so a "
                        + "dev default here would accept forged tokens in production. Refusing to start.");
                }
            }
            if (KNOWN_INSECURE_DEFAULTS.contains(cryptoSecret)) {
                throw new IllegalStateException(
                    "app.crypto.secret is a known insecure default but app.security.require-secure-secrets=true. "
                    + "The APP_CRYPTO_SECRET env var (GCP Secret Manager `wf-app-crypto-secret`) was not injected. Refusing to start.");
            }
            log.info("Secret hygiene checks passed (secure-secrets enforcement ON).");
        } else {
            if (KNOWN_INSECURE_DEFAULTS.contains(jwtSecret) || KNOWN_INSECURE_DEFAULTS.contains(cryptoSecret)) {
                log.warn("Running with dev-only default secrets. This is fine for local development but MUST NOT "
                    + "happen on a real deployment — set APP_REQUIRE_SECURE_SECRETS=true there to enforce.");
            }
        }
    }
}
