package tech.cwvermaak.intellisso.service.security;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import tech.cwvermaak.intellisso.model.User;
import tech.cwvermaak.intellisso.repository.UserRepository;
import tech.cwvermaak.intellisso.service.audit.AuditEventTypes;
import tech.cwvermaak.intellisso.service.audit.AuditService;

import java.time.LocalDateTime;

/**
 * Tracks consecutive failed login attempts per user and locks the account
 * once the configured threshold is reached. Successful logins reset the
 * counter.
 *
 * The service is the single place that decides whether a given user row
 * is currently locked — {@link AuthService} consults it on every login
 * attempt before comparing passwords.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class AccountLockoutService {

    public static final String AUDIT_ACCOUNT_LOCKED = "auth.account.locked";
    public static final String AUDIT_ACCOUNT_UNLOCK_ATTEMPT_ON_LOCKED = "auth.login.while_locked";

    private final UserRepository userRepository;
    private final AccountLockoutProperties properties;
    private final AuditService auditService;

    /**
     * Throws {@link AccountLockedException} if the user is currently locked.
     * Auto-unlocks once the lock window has elapsed.
     */
    @Transactional
    public void ensureNotLocked(User user) {
        LocalDateTime until = user.getLockedUntil();
        if (until == null) return;
        LocalDateTime now = LocalDateTime.now();
        if (now.isBefore(until)) {
            auditService.recordUserAction(AUDIT_ACCOUNT_UNLOCK_ATTEMPT_ON_LOCKED, user,
                    AuditEventTypes.TARGET_USER, String.valueOf(user.getId()),
                    AuditService.meta("locked_until", until.toString()));
            throw new AccountLockedException(until);
        }
        // Window has elapsed — clear the lock and reset the counter so the
        // user can try again with a clean slate.
        user.setLockedUntil(null);
        user.setFailedLoginAttempts(0);
        userRepository.save(user);
    }

    /**
     * Record a failed attempt. If the threshold is reached, the account is
     * locked for the configured window and a high-visibility audit event
     * is emitted.
     */
    @Transactional
    public void recordFailure(User user) {
        int attempts = user.getFailedLoginAttempts() + 1;
        user.setFailedLoginAttempts(attempts);

        if (attempts >= properties.getMaxAttempts()) {
            LocalDateTime until = LocalDateTime.now().plusMinutes(properties.getLockMinutes());
            user.setLockedUntil(until);
            userRepository.save(user);
            log.warn("Account locked: user_id={} tenant={} until={}",
                    user.getId(),
                    user.getTenant() != null ? user.getTenant().getSlug() : "?",
                    until);
            auditService.recordUserAction(AUDIT_ACCOUNT_LOCKED, user,
                    AuditEventTypes.TARGET_USER, String.valueOf(user.getId()),
                    AuditService.meta(
                            "attempts", attempts,
                            "locked_until", until.toString(),
                            "lock_minutes", properties.getLockMinutes()));
            return;
        }

        userRepository.save(user);
    }

    /** Successful login — reset the counter. */
    @Transactional
    public void recordSuccess(User user) {
        if (user.getFailedLoginAttempts() == 0 && user.getLockedUntil() == null) return;
        user.setFailedLoginAttempts(0);
        user.setLockedUntil(null);
        userRepository.save(user);
    }
}
