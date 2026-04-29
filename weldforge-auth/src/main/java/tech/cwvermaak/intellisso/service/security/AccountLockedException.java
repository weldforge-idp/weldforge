package tech.cwvermaak.intellisso.service.security;

import org.springframework.security.core.AuthenticationException;

import java.time.LocalDateTime;

/**
 * Raised when a login attempt hits a locked account. Carries the unlock
 * timestamp so the UI can show a sensible message — but the outward
 * response to the user stays deliberately vague ("invalid credentials")
 * to avoid leaking the account-exists / locked-out distinction to an
 * attacker running enumeration.
 */
public class AccountLockedException extends AuthenticationException {

    private final LocalDateTime lockedUntil;

    public AccountLockedException(LocalDateTime lockedUntil) {
        super("Account is locked");
        this.lockedUntil = lockedUntil;
    }

    public LocalDateTime getLockedUntil() {
        return lockedUntil;
    }
}
