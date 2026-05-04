package tech.cwvermaak.weldforge.service.security;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import tech.cwvermaak.weldforge.model.Tenant;
import tech.cwvermaak.weldforge.model.User;
import tech.cwvermaak.weldforge.repository.UserRepository;
import tech.cwvermaak.weldforge.service.audit.AuditService;

import java.time.LocalDateTime;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

class AccountLockoutServiceTest {

    private UserRepository userRepository;
    private AuditService auditService;
    private AccountLockoutProperties props;
    private AccountLockoutService service;
    private User user;

    @BeforeEach
    void setUp() {
        userRepository = mock(UserRepository.class);
        auditService = mock(AuditService.class);
        props = new AccountLockoutProperties();
        props.setMaxAttempts(3);
        props.setLockMinutes(10);
        service = new AccountLockoutService(userRepository, props, auditService);

        Tenant t = Tenant.builder().id(1L).slug("acme").name("Acme").build();
        user = User.builder().id(42L).tenant(t).email("alice@acme.test").build();
    }

    @Test
    @DisplayName("a fresh account is not locked")
    void freshAccount_notLocked() {
        assertThatCode(() -> service.ensureNotLocked(user))
                .doesNotThrowAnyException();
    }

    @Test
    @DisplayName("recording N-1 failures does not lock the account")
    void underThreshold_doesNotLock() {
        service.recordFailure(user);
        service.recordFailure(user);

        assertThat(user.getFailedLoginAttempts()).isEqualTo(2);
        assertThat(user.getLockedUntil()).isNull();
        verify(auditService, never()).recordUserAction(
                eq(AccountLockoutService.AUDIT_ACCOUNT_LOCKED), any(), any(), any(), any());
    }

    @Test
    @DisplayName("crossing the threshold sets locked_until and emits an audit event")
    void threshold_locksAndAudits() {
        service.recordFailure(user);
        service.recordFailure(user);
        service.recordFailure(user);

        assertThat(user.getFailedLoginAttempts()).isEqualTo(3);
        assertThat(user.getLockedUntil()).isNotNull();
        assertThat(user.getLockedUntil()).isAfter(LocalDateTime.now());
        verify(auditService).recordUserAction(
                eq(AccountLockoutService.AUDIT_ACCOUNT_LOCKED),
                eq(user), any(), any(), any());
    }

    @Test
    @DisplayName("ensureNotLocked throws while the lock window is active")
    void lockWindow_throws() {
        user.setLockedUntil(LocalDateTime.now().plusMinutes(5));

        assertThatThrownBy(() -> service.ensureNotLocked(user))
                .isInstanceOf(AccountLockedException.class);
        verify(auditService).recordUserAction(
                eq(AccountLockoutService.AUDIT_ACCOUNT_UNLOCK_ATTEMPT_ON_LOCKED),
                eq(user), any(), any(), any());
    }

    @Test
    @DisplayName("ensureNotLocked auto-unlocks once the window has elapsed")
    void elapsedWindow_autoUnlocks() {
        user.setLockedUntil(LocalDateTime.now().minusMinutes(1));
        user.setFailedLoginAttempts(5);

        service.ensureNotLocked(user);

        assertThat(user.getLockedUntil()).isNull();
        assertThat(user.getFailedLoginAttempts()).isZero();
    }

    @Test
    @DisplayName("successful login resets the counter and clears the lock")
    void success_resets() {
        user.setFailedLoginAttempts(2);

        service.recordSuccess(user);

        assertThat(user.getFailedLoginAttempts()).isZero();
        assertThat(user.getLockedUntil()).isNull();
    }
}
