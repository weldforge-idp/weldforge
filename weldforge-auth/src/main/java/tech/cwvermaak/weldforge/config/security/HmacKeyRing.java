package tech.cwvermaak.weldforge.config.security;

import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * The platform HMAC key ring: one key signs, several may verify.
 *
 * <p><b>Why this exists (B-JWT-2 / CONF-7.4).</b> {@code app.jwt.secret} is
 * shared verbatim with external consumers, so with a single key rotation was an
 * all-or-nothing cutover: the moment the secret changed, every token signed
 * under the old one failed verification in WeldForge <em>and</em> in every
 * consumer, simultaneously. You could not stage it. A key ring removes that
 * lockstep — during an overlap window the new key signs while the old one still
 * verifies, so the systems can move one at a time.
 *
 * <p><b>Previous keys verify and never sign.</b> That asymmetry is the whole
 * safety property. {@link #signingKey()} returns exactly one key, so no amount
 * of configuration can cause a token to be minted under a retired secret.
 *
 * <p><b>Every key in the ring is held to the same floor.</b> A verification key
 * is as powerful as a signing key for the purpose that matters — anyone holding
 * it can mint a token this server will accept — so a weak entry here would be a
 * forgery oracle, not merely untidy. {@link SecretHygieneValidator} enforces the
 * 64-byte HS512 minimum and the known-insecure-default check across the whole
 * ring, not just the signing key. Boot fails rather than warns.
 *
 * <p>That floor doubles as a guard against the one configuration mistake this
 * format invites. The list is comma-separated, so a secret containing a comma
 * would be split into fragments — and every fragment would be far shorter than
 * 64 bytes, which is a hard boot failure rather than a server that quietly
 * trusts nonsense.
 *
 * <p><b>The {@code kid} header</b> is published on every token this server
 * signs, derived from the key itself ({@link #keyId}) rather than configured
 * separately, so a consumer can compute the same id from its own copy of the
 * secret with nothing to keep in step. Verification uses it as a hint only: an
 * unrecognised or absent {@code kid} falls back to trying the ring, because a
 * token minted by an older build carries no {@code kid} at all and must keep
 * working through the upgrade.
 */
@Slf4j
public final class HmacKeyRing {

    /** The configured values this ring was built from, so a caller can tell when to rebuild. */
    private final String sourceSecret;
    private final String sourcePrevious;

    private final SecretKey signing;
    private final String signingKid;
    /** Insertion-ordered: signing key first, then retired keys newest first. */
    private final Map<String, SecretKey> ring;

    /**
     * Build a ring from the configured values.
     *
     * @param secret          the active signing secret ({@code app.jwt.secret})
     * @param previousSecrets retired secrets still accepted for verification,
     *                        comma-separated, newest first
     *                        ({@code app.jwt.previous-secrets}, env
     *                        {@code APP_JWT_PREVIOUS_SECRETS}). Normally empty;
     *                        holds one value during a rotation overlap.
     */
    public static HmacKeyRing of(String secret, String previousSecrets) {
        return new HmacKeyRing(secret, previousSecrets);
    }

    private HmacKeyRing(String secret, String previousSecrets) {
        this.sourceSecret = secret;
        this.sourcePrevious = previousSecrets;
        this.signing = toKey(secret);
        this.signingKid = keyId(secret);

        Map<String, SecretKey> built = new LinkedHashMap<>();
        built.put(signingKid, signing);

        for (String previous : parse(previousSecrets)) {
            String kid = keyId(previous);
            // A retired secret equal to the active one is a no-op rather than an
            // error: it happens when an operator populates the overlap list
            // before swapping the active key, and failing the boot for it would
            // punish the careful order.
            if (built.containsKey(kid)) {
                continue;
            }
            built.put(kid, toKey(previous));
        }

        this.ring = java.util.Collections.unmodifiableMap(built);
        if (built.size() > 1) {
            log.warn("HMAC key ring holds {} keys: signing kid={}, also verifying {}. "
                            + "This is a rotation overlap window -- remove the retired secrets from "
                            + "app.jwt.previous-secrets once no token signed under them can still be live "
                            + "(one access-token TTL after every consumer has moved).",
                    built.size(), signingKid,
                    built.keySet().stream().filter(k -> !k.equals(signingKid)).toList());
        } else {
            log.info("HMAC key ring holds one key, kid={} (no rotation in progress).", signingKid);
        }
    }

    /** Whether this ring reflects the given configuration, or must be rebuilt. */
    public boolean wasBuiltFrom(String secret, String previousSecrets) {
        return java.util.Objects.equals(sourceSecret, secret)
                && java.util.Objects.equals(sourcePrevious, previousSecrets);
    }

    /** The one key that signs. Never a retired key. */
    public SecretKey signingKey() {
        return signing;
    }

    /** The {@code kid} stamped on tokens this server signs. */
    public String signingKeyId() {
        return signingKid;
    }

    /** A key by its id, for the {@code kid}-directed fast path. */
    public Optional<SecretKey> keyById(String kid) {
        return kid == null ? Optional.empty() : Optional.ofNullable(ring.get(kid));
    }

    /**
     * Every key that may verify, signing key first.
     *
     * <p>Ordered so the common case — a token this server signed moments ago —
     * matches on the first attempt, and a retired key is only reached by a token
     * that genuinely needs it.
     */
    public List<Map.Entry<String, SecretKey>> verificationKeys() {
        return List.copyOf(ring.entrySet());
    }

    /** True while retired keys are still accepted. */
    public boolean rotationInProgress() {
        return ring.size() > 1;
    }

    /**
     * The id for a secret: the first 16 hex characters of its SHA-256.
     *
     * <p>Derived rather than configured so two systems holding the same secret
     * agree on its id with nothing to coordinate. Publishing it discloses
     * nothing: the input is a 64-byte high-entropy secret, so the digest is not
     * invertible, and only the holder of the secret can produce a matching one.
     */
    public static String keyId(String secret) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(secret.getBytes(StandardCharsets.UTF_8));
            StringBuilder hex = new StringBuilder(16);
            for (int i = 0; i < 8; i++) {
                hex.append(String.format("%02x", digest[i]));
            }
            return hex.toString();
        } catch (NoSuchAlgorithmException e) {
            // SHA-256 is mandated by the JCA spec; absent means a broken JRE.
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    /** Split the configured list, dropping blanks. */
    public static List<String> parse(String configured) {
        if (configured == null || configured.isBlank()) {
            return List.of();
        }
        List<String> out = new ArrayList<>();
        for (String part : configured.split(",")) {
            String trimmed = part.trim();
            if (!trimmed.isEmpty()) {
                out.add(trimmed);
            }
        }
        return List.copyOf(out);
    }

    private static SecretKey toKey(String value) {
        return Keys.hmacShaKeyFor(value.getBytes(StandardCharsets.UTF_8));
    }
}
