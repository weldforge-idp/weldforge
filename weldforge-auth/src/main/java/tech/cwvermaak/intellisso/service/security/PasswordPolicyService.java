package tech.cwvermaak.intellisso.service.security;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * Validates a submitted password against the deployment's
 * {@link PasswordPolicyProperties}. Called from the registration flow and
 * from any future "change password" flow.
 *
 * The service is pure: no DB, no side effects, no audit — it throws a
 * {@link PasswordPolicyViolation} on failure and callers decide how to
 * record the attempt.
 */
@Service
@RequiredArgsConstructor
public class PasswordPolicyService {

    private final PasswordPolicyProperties properties;

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
