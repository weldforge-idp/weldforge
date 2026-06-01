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

    @Test
    void badCurrentPassword_audits_withReasonMetadata() {
        recorder.badCurrentPassword(user);

        verify(auditService).recordUserAction(
                eq(AuditEventTypes.AUTH_PASSWORD_CHANGE_FAILED),
                eq(user),
                eq(AuditEventTypes.TARGET_USER),
                eq("42"),
                eq(AuditService.meta("reason", "bad_current_password")));
        verifyNoInteractions(lockoutService);
        // changePassword failure isn't a "login" — don't bump the login counter.
        assertThat(meterRegistry.counter("sso.auth.login", "outcome", "failure", "tenant", "acme").count())
                .isEqualTo(0.0);
    }
}
