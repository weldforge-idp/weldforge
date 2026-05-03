package tech.cwvermaak.weldforge.service.security;

import java.util.List;

/**
 * Thrown when a submitted password fails the configured policy. Carries a
 * list of human-readable reasons so the UI can render all violations at once
 * instead of whack-a-moling through one error at a time.
 */
public class PasswordPolicyViolation extends RuntimeException {

    private final List<String> reasons;

    public PasswordPolicyViolation(List<String> reasons) {
        super("Password does not meet policy: " + String.join("; ", reasons));
        this.reasons = List.copyOf(reasons);
    }

    public List<String> getReasons() {
        return reasons;
    }
}
