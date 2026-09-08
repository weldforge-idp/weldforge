package tech.cwvermaak.weldforge.service.security;

import tech.cwvermaak.weldforge.model.MfaFactorType;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Builds the {@code amr} claim — "authentication methods references", the
 * record of <em>how</em> a user actually proved who they are on this login.
 * Values are the RFC 8176 registered identifiers.
 *
 * <p>Relying parties use this to make authorisation decisions the token alone
 * could not support. A vault or a secrets store may accept a session only when
 * it was established with a phishing-resistant factor, which is a different
 * question from "does this user have a security key enrolled" — enrolment says
 * what they <em>could</em> have used, {@code amr} says what they
 * <em>did</em> use. That distinction is the whole value of the claim, so
 * nothing here may report a factor that was not exercised in this login.
 *
 * <p>The claim is deliberately assembled at the point of authentication and
 * carried forward (session token → authorization code → OIDC tokens) rather
 * than recomputed later from the user's enrolled factors, which would silently
 * turn it into the weaker "could have" statement.
 */
public final class AuthenticationMethods {

    /** RFC 8176: password-based authentication. */
    public static final String PASSWORD = "pwd";
    /** RFC 8176: one-time password — TOTP, and one-time backup codes. */
    public static final String OTP = "otp";
    /** RFC 8176: confirmation by SMS. */
    public static final String SMS = "sms";
    /**
     * RFC 8176: proof-of-possession of a hardware-secured key. WebAuthn
     * assertions are reported as this. A platform authenticator backed by a
     * TPM or a secure enclave is hardware-secured too; distinguishing a
     * roaming key from a platform one would need the authenticator attachment,
     * which is not retained at registration. Both are phishing-resistant,
     * which is the property relying parties gate on.
     */
    public static final String HARDWARE_KEY = "hwk";
    /** RFC 8176: multiple-factor authentication was performed. */
    public static final String MULTIPLE_FACTOR = "mfa";

    private AuthenticationMethods() {
    }

    /** A password was verified and nothing else — no second factor. */
    public static List<String> password() {
        return List.of(PASSWORD);
    }

    /**
     * A password was verified and then a second factor was satisfied.
     *
     * @param factor     the factor presented, or null when a backup code was
     *                   used (the backup-code path is independent of the
     *                   requested type — see {@code MfaService.verifyChallenge})
     * @param backupCode true when a one-time backup code was redeemed
     */
    public static List<String> passwordAnd(MfaFactorType factor, boolean backupCode) {
        List<String> methods = new ArrayList<>();
        methods.add(PASSWORD);
        methods.add(backupCode ? OTP : forFactor(factor));
        methods.add(MULTIPLE_FACTOR);
        return List.copyOf(methods);
    }

    /** The RFC 8176 identifier for a second-factor type. */
    public static String forFactor(MfaFactorType factor) {
        if (factor == null) {
            return OTP;
        }
        return switch (factor) {
            case TOTP -> OTP;
            case SMS -> SMS;
            case WEBAUTHN -> HARDWARE_KEY;
        };
    }

    /**
     * Serialise for storage as a single column. Space-separated, matching how
     * {@code amr} travels in a JWT and in the {@code scope} parameter.
     */
    public static String toStorage(List<String> methods) {
        return methods == null || methods.isEmpty() ? null : String.join(" ", methods);
    }

    /** Read back {@link #toStorage(List)}; null or blank yields an empty list. */
    public static List<String> fromStorage(String stored) {
        if (stored == null || stored.isBlank()) {
            return List.of();
        }
        return Arrays.stream(stored.trim().split("\\s+"))
                .filter(v -> !v.isBlank())
                .toList();
    }
}
