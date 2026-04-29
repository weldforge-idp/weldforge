package tech.cwvermaak.intellisso.service.security;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

/**
 * Central point for hashing API keys and service-account tokens (PRD TOK-01 / TOK-03).
 * Hashing is deliberately a plain SHA-256: the keys already carry 192 bits of
 * entropy (24 random bytes) so there is no password-style dictionary risk
 * that would justify a slow KDF. A fast hash lets the auth filter lookup by
 * hash in O(1) without widening our latency budget.
 */
public final class ApiKeyHasher {

    public static final String LIVE_KEY_PREFIX = "wf_live_";
    public static final String SERVICE_ACCOUNT_PREFIX = "wf_svc_";
    public static final int DISPLAY_PREFIX_LENGTH = 12;

    private ApiKeyHasher() {}

    public static String hash(String raw) {
        if (raw == null) return null;
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(md.digest(raw.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    /** First 12 characters of the raw key — safe to store and display. */
    public static String displayPrefix(String raw) {
        if (raw == null) return null;
        return raw.length() <= DISPLAY_PREFIX_LENGTH ? raw : raw.substring(0, DISPLAY_PREFIX_LENGTH);
    }
}
