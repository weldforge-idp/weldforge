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
     * current password.
     */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void badCurrentPassword(User user) {
        auditService.recordUserAction(AuditEventTypes.AUTH_PASSWORD_CHANGE_FAILED, user,
                AuditEventTypes.TARGET_USER, String.valueOf(user.getId()),
                AuditService.meta("reason", "bad_current_password"));
    }

    private void bumpFailureCounter(Tenant tenant) {
        meterRegistry.counter(LOGIN_COUNTER, "outcome", "failure", "tenant", tenant.getSlug()).increment();
    }
}
