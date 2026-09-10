package tech.cwvermaak.weldforge.service.security;

import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * Validates a submitted password against the deployment's
 * {@link PasswordPolicyProperties}. Called from registration, the
 * self-service password change and password reset.
 *
 * <p>No DB, no audit -- it throws a {@link PasswordPolicyViolation} on failure
 * and callers decide how to record the attempt. The one side effect is the
 * breached-password lookup (CONF-7.1), which sends a five-character hash
 * prefix and never the password; see {@link PwnedPasswordsScreen}.
 */
@Service
public class PasswordPolicyService {

    /**
     * Says why, not just that: a user told only "invalid password" retries a
     * variation of the same breached password.
     */
    public static final String BREACHED_REASON =
            "must not appear in a known data breach, and this one does; choose a different password";

    private final PasswordPolicyProperties properties;
    private final BreachedPasswordScreen breachScreen;

    public PasswordPolicyService(PasswordPolicyProperties properties, BreachedPasswordScreen breachScreen) {
        this.properties = properties;
        this.breachScreen = breachScreen;
    }

    public void validate(String password) {
        List<String> reasons = new ArrayList<>();

        if (password == null || password.isEmpty()) {
            reasons.add("password is required");
            throw new PasswordPolicyViolation(reasons);
        }

        int length = password.length();
        if (length < properties.getMinLength()) {
            reasons.add("at least " + properties.getMinLength() + " characters");
        }
        // bcrypt truncates at 72 bytes — anything longer would silently ignore
        // the tail and weaken the hash. Reject up-front.
        int utf8Bytes = password.getBytes(StandardCharsets.UTF_8).length;
        if (utf8Bytes > properties.getMaxLength()) {
            reasons.add("at most " + properties.getMaxLength() + " bytes");
        }

        // Off by default (NIST SP 800-63B §5.1.1.2); a deployment may still
        // turn any of them back on.
        if (properties.isRequireUppercase() && !containsUppercase(password)) {
            reasons.add("at least one uppercase letter");
        }
        if (properties.isRequireLowercase() && !containsLowercase(password)) {
            reasons.add("at least one lowercase letter");
        }
        if (properties.isRequireDigit() && !containsDigit(password)) {
            reasons.add("at least one digit");
        }
        if (properties.isRequireSymbol() && !containsSymbol(password)) {
            reasons.add("at least one symbol (non-alphanumeric character)");
        }

        // Screened last, and only once everything local passes: a password
        // refused anyway need not cost a round-trip to the corpus. UNAVAILABLE
        // is accepted -- the screen has already logged and counted it.
        if (reasons.isEmpty()
                && breachScreen.check(password) == BreachedPasswordScreen.Result.BREACHED) {
            reasons.add(BREACHED_REASON);
        }

        if (!reasons.isEmpty()) {
            throw new PasswordPolicyViolation(reasons);
        }
    }

    private static boolean containsUppercase(String s) {
        for (int i = 0; i < s.length(); i++) if (Character.isUpperCase(s.charAt(i))) return true;
        return false;
    }

    private static boolean containsLowercase(String s) {
        for (int i = 0; i < s.length(); i++) if (Character.isLowerCase(s.charAt(i))) return true;
        return false;
    }

    private static boolean containsDigit(String s) {
        for (int i = 0; i < s.length(); i++) if (Character.isDigit(s.charAt(i))) return true;
        return false;
    }

    private static boolean containsSymbol(String s) {
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (!Character.isLetterOrDigit(c) && !Character.isWhitespace(c)) return true;
        }
        return false;
    }
}
