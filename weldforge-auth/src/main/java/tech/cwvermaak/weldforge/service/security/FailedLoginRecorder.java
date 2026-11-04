package tech.cwvermaak.weldforge.service.security;

import io.micrometer.core.instrument.MeterRegistry;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import tech.cwvermaak.weldforge.model.AuditEvent;
import tech.cwvermaak.weldforge.model.Tenant;
import tech.cwvermaak.weldforge.model.User;
import tech.cwvermaak.weldforge.service.audit.AuditEventTypes;
import tech.cwvermaak.weldforge.service.audit.AuditService;

import java.util.Map;

/**
 * Records the side-effects of a failed authentication in a fresh transaction
 * so they survive the caller's rollback.
 *
 * <p>The {@code BadCredentialsException} thrown immediately after a login
 * failure rolls back the surrounding {@code @Transactional} boundary in
 * {@link tech.cwvermaak.weldforge.service.AuthService}. Without an external
 * transaction the audit row and the {@code failed_login_attempts} bump are
 * rolled back too — failed logins never appear in the audit log and the
 * lockout counter never increments, so brute-force protection silently does
 * nothing.
 *
 * <p>{@link AuditService#log} already declares {@code REQUIRES_NEW}, but the
 * convenience methods that callers actually use ({@code recordAnonymous},
 * {@code recordUserAction}) reach it via an internal self-call that bypasses
 * the Spring proxy — so the annotation is silently ignored when the caller
 * is itself inside a transaction. The same self-call hazard applies to
 * {@link AccountLockoutService#recordFailure}.
 *
 * <p>This bean lives outside both of those services, so every entry-point
 * is a cross-bean call: the {@code REQUIRES_NEW} below actually engages,
 * the new transaction commits independently, and the parent's rollback
 * can no longer erase the failure record.
 */
@Component
@RequiredArgsConstructor
public class FailedLoginRecorder {

    private static final String LOGIN_COUNTER = "sso.auth.login";

    private final AuditService auditService;
    private final AccountLockoutService lockoutService;
    private final MeterRegistry meterRegistry;

    /** Failed login against a tenant where the supplied identifier matched no user. */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void unknownUser(Tenant tenant, String identifier) {
        bumpFailureCounter(tenant);
        auditService.recordAnonymous(AuditEventTypes.AUTH_LOGIN_FAILED,
                AuditEvent.Outcome.FAILURE, tenant.getId(),
                identifier, AuditEventTypes.TARGET_USER, null,
                AuditService.meta("reason", "unknown_user"));
    }

    /**
     * Failed login against a deactivated user (SCIM-disabled or admin-disabled).
     * {@code source} is non-null when the credential came from an upstream
     * directory (e.g. {@code "ldap"}), otherwise null for the local path.
     */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void inactiveUser(Tenant tenant, User user, String identifier, String source) {
        bumpFailureCounter(tenant);
        Map<String, Object> meta = source != null
                ? AuditService.meta("reason", "user_inactive", "source", source)
                : AuditService.meta("reason", "user_inactive");
        auditService.recordAnonymous(AuditEventTypes.AUTH_LOGIN_FAILED,
                AuditEvent.Outcome.FAILURE, tenant.getId(),
                identifier, AuditEventTypes.TARGET_USER,
                String.valueOf(user.getId()),
                meta);
    }

    /**
     * Failed local-password login. Records the audit row, increments the
     * lockout counter (locking the account once the threshold is reached),
     * and bumps the failure metric.
     */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void badPassword(Tenant tenant, User user, String identifier) {
        lockoutService.recordFailure(user);
        bumpFailureCounter(tenant);
        auditService.recordAnonymous(AuditEventTypes.AUTH_LOGIN_FAILED,
                AuditEvent.Outcome.FAILURE, tenant.getId(),
                identifier, AuditEventTypes.TARGET_USER,
                String.valueOf(user.getId()),
                AuditService.meta("reason", "bad_password"));
    }

    /**
     * Failed self-service password change — the user supplied the wrong
     * current password (B-AUTH-6, F61).
     *
     * <p>Until F61 this audited and returned, so {@code /api/auth/change-password}
     * answered password guesses at full speed with nothing recorded but a row
     * nothing alerts on. It now feeds the account lockout, for the same reason
     * {@link #badResetPassword(User)} does: the per-IP bucket beside it is
     * defeated by rotating source addresses, and the per-user counter is not.
     *
     * <p>That this can lock an already-authenticated account is the intended
     * behaviour and not a new exposure. {@link #badPassword} already feeds the
     * same counter from {@code /api/auth/login}, which needs no token at all — so
     * anyone holding an email address could already lock that account for the
     * configured window. This closes an oracle without handing out a lever that
     * was not already lying around in a weaker position.
     *
     * @return the lock expiry if this failure was the one that tripped the lock,
     *         otherwise {@code null}. The caller uses it to answer 423 with a
     *         wait rather than a bare 401, so the user is told what happened at
     *         the moment it happens instead of on their next attempt.
     */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public java.time.LocalDateTime badCurrentPassword(User user) {
        lockoutService.recordFailure(user);
        java.time.LocalDateTime lockedUntil = user.getLockedUntil();
        auditService.recordUserAction(AuditEventTypes.AUTH_PASSWORD_CHANGE_FAILED, user,
                AuditEventTypes.TARGET_USER, String.valueOf(user.getId()),
                AuditService.meta("reason", "bad_current_password",
                        "locked", lockedUntil != null));
        return lockedUntil;
    }

    /**
     * Failed self-service MFA reset: the user supplied the wrong current
     * password (B-AUTH-5, F60).
     *
     * <p>Unlike {@link #badCurrentPassword(User)} this <em>does</em> feed the
     * account lockout, because the endpoint it guards is reachable with a
     * stolen access token and used to answer password guesses at full speed
     * with nothing recorded at all. The per-IP rate-limit bucket added
     * alongside is defeated by rotating source addresses; this counter is not,
     * which makes it the control that actually closes the oracle.
     */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void badResetPassword(User user) {
        lockoutService.recordFailure(user);
        auditService.recordUserAction(AuditEventTypes.AUTH_MFA_RESET_DENIED, user,
                AuditEventTypes.TARGET_USER, String.valueOf(user.getId()),
                AuditService.meta("reason", "bad_password"));
    }

    private void bumpFailureCounter(Tenant tenant) {
        meterRegistry.counter(LOGIN_COUNTER, "outcome", "failure", "tenant", tenant.getSlug()).increment();
    }
}
