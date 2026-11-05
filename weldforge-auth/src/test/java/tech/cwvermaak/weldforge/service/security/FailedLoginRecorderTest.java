package tech.cwvermaak.weldforge.service.security;

import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import tech.cwvermaak.weldforge.model.AuditEvent;
import tech.cwvermaak.weldforge.model.Tenant;
import tech.cwvermaak.weldforge.model.User;
import tech.cwvermaak.weldforge.service.audit.AuditEventTypes;
import tech.cwvermaak.weldforge.service.audit.AuditService;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

class FailedLoginRecorderTest {

    private AuditService auditService;
    private AccountLockoutService lockoutService;
    private MeterRegistry meterRegistry;
    private FailedLoginRecorder recorder;

    private Tenant tenant;
    private User user;

    @BeforeEach
    void setUp() {
        auditService = mock(AuditService.class);
        lockoutService = mock(AccountLockoutService.class);
        meterRegistry = new SimpleMeterRegistry();
        recorder = new FailedLoginRecorder(auditService, lockoutService, meterRegistry);

        tenant = Tenant.builder().id(7L).slug("acme").name("Acme").build();
        user = User.builder().id(42L).tenant(tenant).email("alice@acme.test").build();
    }

    @Test
    void unknownUser_audits_andBumpsMetric_andDoesNotTouchLockout() {
        recorder.unknownUser(tenant, "ghost@acme.test");

        verify(auditService).recordAnonymous(
                eq(AuditEventTypes.AUTH_LOGIN_FAILED),
                eq(AuditEvent.Outcome.FAILURE),
                eq(7L),
                eq("ghost@acme.test"),
                eq(AuditEventTypes.TARGET_USER),
                eq(null),
                eq(AuditService.meta("reason", "unknown_user")));
        verifyNoInteractions(lockoutService);
        assertThat(meterRegistry.counter("sso.auth.login", "outcome", "failure", "tenant", "acme").count())
                .isEqualTo(1.0);
    }

    @Test
    void inactiveUser_localPath_omitsSourceMetadata() {
        recorder.inactiveUser(tenant, user, "alice@acme.test", null);

        verify(auditService).recordAnonymous(
                eq(AuditEventTypes.AUTH_LOGIN_FAILED),
                eq(AuditEvent.Outcome.FAILURE),
                eq(7L),
                eq("alice@acme.test"),
                eq(AuditEventTypes.TARGET_USER),
                eq("42"),
                eq(AuditService.meta("reason", "user_inactive")));
        verifyNoInteractions(lockoutService);
    }

    @Test
    void inactiveUser_ldapPath_includesSourceMetadata() {
        recorder.inactiveUser(tenant, user, "alice@acme.test", "ldap");

        Map<String, Object> expectedMeta = AuditService.meta("reason", "user_inactive", "source", "ldap");
        verify(auditService).recordAnonymous(
                eq(AuditEventTypes.AUTH_LOGIN_FAILED),
                eq(AuditEvent.Outcome.FAILURE),
                eq(7L),
                eq("alice@acme.test"),
                eq(AuditEventTypes.TARGET_USER),
                eq("42"),
                eq(expectedMeta));
    }

    @Test
    void badPassword_bumpsLockout_audits_andIncrementsMetric() {
        recorder.badPassword(tenant, user, "alice@acme.test");

        verify(lockoutService).recordFailure(user);
        verify(auditService).recordAnonymous(
                eq(AuditEventTypes.AUTH_LOGIN_FAILED),
                eq(AuditEvent.Outcome.FAILURE),
                eq(7L),
                eq("alice@acme.test"),
                eq(AuditEventTypes.TARGET_USER),
                eq("42"),
                eq(AuditService.meta("reason", "bad_password")));
        assertThat(meterRegistry.counter("sso.auth.login", "outcome", "failure", "tenant", "acme").count())
                .isEqualTo(1.0);
    }

    /**
     * B-AUTH-6 (F61). This test previously asserted
     * {@code verifyNoInteractions(lockoutService)} — it encoded the defect: a
     * wrong current password was audited and nothing else, so the endpoint
     * answered password guesses at full speed and the lockout never saw them.
     */
    @Test
    void badCurrentPassword_recordsFailure_andAudits_whenNotYetLocked() {
        java.time.LocalDateTime lockedUntil = recorder.badCurrentPassword(user);

        verify(lockoutService).recordFailure(user);
        assertThat(lockedUntil).isNull();
        verify(auditService).recordUserAction(
                eq(AuditEventTypes.AUTH_PASSWORD_CHANGE_FAILED),
                eq(user),
                eq(AuditEventTypes.TARGET_USER),
                eq("42"),
                eq(AuditService.meta("reason", "bad_current_password", "locked", false)));
        // changePassword failure isn't a "login" — don't bump the login counter.
        assertThat(meterRegistry.counter("sso.auth.login", "outcome", "failure", "tenant", "acme").count())
                .isEqualTo(0.0);
    }

    /**
     * When the failure is the one that trips the lock, the expiry comes back so
     * the caller can answer 423 with a wait immediately, rather than a bare 401
     * that leaves the user to discover the lock on their next attempt.
     */
    @Test
    void badCurrentPassword_returnsLockExpiry_whenThisFailureLockedTheAccount() {
        java.time.LocalDateTime until = java.time.LocalDateTime.now().plusMinutes(15);
        doAnswer(inv -> {
            user.setLockedUntil(until);
            return null;
        }).when(lockoutService).recordFailure(user);

        java.time.LocalDateTime lockedUntil = recorder.badCurrentPassword(user);

        assertThat(lockedUntil).isEqualTo(until);
        verify(auditService).recordUserAction(
                eq(AuditEventTypes.AUTH_PASSWORD_CHANGE_FAILED),
                eq(user),
                eq(AuditEventTypes.TARGET_USER),
                eq("42"),
                eq(AuditService.meta("reason", "bad_current_password", "locked", true)));
    }
}
