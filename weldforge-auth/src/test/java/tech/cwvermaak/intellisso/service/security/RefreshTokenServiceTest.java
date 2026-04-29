package tech.cwvermaak.intellisso.service.security;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.security.authentication.BadCredentialsException;
import tech.cwvermaak.intellisso.model.RefreshToken;
import tech.cwvermaak.intellisso.model.Tenant;
import tech.cwvermaak.intellisso.model.User;
import tech.cwvermaak.intellisso.repository.RefreshTokenRepository;
import tech.cwvermaak.intellisso.service.audit.AuditService;

import java.time.LocalDateTime;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicLong;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

/**
 * Contract tests for {@link RefreshTokenService}. The central invariant is
 * reuse detection: presenting a token that has already been used must
 * revoke every descendant in the family and emit a DENIED audit event.
 */
class RefreshTokenServiceTest {

    private RefreshTokenRepository repo;
    private AuditService auditService;
    private RefreshTokenProperties props;
    private RefreshTokenService service;
    private User user;

    @BeforeEach
    void setUp() {
        repo = mock(RefreshTokenRepository.class);
        auditService = mock(AuditService.class);
        props = new RefreshTokenProperties();
        props.setLifetimeDays(7);
        service = new RefreshTokenService(repo, props, auditService);

        Tenant t = Tenant.builder().id(1L).slug("acme").name("Acme").build();
        user = User.builder().id(42L).tenant(t).email("alice@acme.test").build();

        // save() echoes the row back with a generated id so the caller can
        // still read expiresAt etc.
        AtomicLong idSeq = new AtomicLong(1);
        when(repo.save(any(RefreshToken.class))).thenAnswer(inv -> {
            RefreshToken r = inv.getArgument(0);
            if (r.getId() == null) r.setId(idSeq.getAndIncrement());
            return r;
        });
    }

    @Test
    @DisplayName("issueNew mints a token in a new family with the configured lifetime")
    void issueNew_mintsFreshFamily() {
        RefreshTokenService.Issued issued = service.issueNew(user, "1.2.3.4", "ua");

        assertThat(issued.rawToken()).isNotBlank();
        assertThat(issued.row().getFamilyId()).isNotNull();
        assertThat(issued.row().getUser()).isSameAs(user);
        assertThat(issued.row().getExpiresAt())
                .isAfter(LocalDateTime.now().plusDays(6))
                .isBefore(LocalDateTime.now().plusDays(8));
        assertThat(issued.row().getTokenHash()).isNotEqualTo(issued.rawToken());
    }

    @Test
    @DisplayName("rotate issues a successor in the same family and marks the original used")
    void rotate_issuesSuccessor() {
        UUID familyId = UUID.randomUUID();
        String existingHash = RefreshTokenService.hash("existing-raw");
        RefreshToken existing = RefreshToken.builder()
                .id(100L)
                .user(user)
                .tenant(user.getTenant())
                .familyId(familyId)
                .tokenHash(existingHash)
                .issuedAt(LocalDateTime.now().minusMinutes(1))
                .expiresAt(LocalDateTime.now().plusDays(7))
                .build();
        when(repo.findByTokenHash(existingHash)).thenReturn(Optional.of(existing));

        RefreshTokenService.Issued issued = service.rotate("existing-raw", "1.2.3.4", "ua");

        assertThat(existing.getUsedAt()).isNotNull();
        assertThat(existing.getReplacedBy()).isNotNull();
        assertThat(issued.row().getFamilyId()).isEqualTo(familyId);
        verify(auditService).recordUserAction(
                eq(RefreshTokenService.AUDIT_REFRESH_ROTATE),
                eq(user), any(), any(), any());
    }

    @Test
    @DisplayName("re-using a token that was already rotated revokes the whole family")
    void reuse_revokesFamily() {
        UUID familyId = UUID.randomUUID();
        String existingHash = RefreshTokenService.hash("stolen-raw");
        RefreshToken alreadyUsed = RefreshToken.builder()
                .id(100L)
                .user(user)
                .tenant(user.getTenant())
                .familyId(familyId)
                .tokenHash(existingHash)
                .issuedAt(LocalDateTime.now().minusMinutes(5))
                .expiresAt(LocalDateTime.now().plusDays(7))
                .usedAt(LocalDateTime.now().minusMinutes(3))
                .build();
        when(repo.findByTokenHash(existingHash)).thenReturn(Optional.of(alreadyUsed));
        when(repo.revokeFamily(eq(familyId), any(), eq("reuse_detected"))).thenReturn(4);

        assertThatThrownBy(() -> service.rotate("stolen-raw", "1.2.3.4", "ua"))
                .isInstanceOf(BadCredentialsException.class);

        verify(repo).revokeFamily(eq(familyId), any(), eq("reuse_detected"));
        ArgumentCaptor<tech.cwvermaak.intellisso.model.AuditEvent.AuditEventBuilder> captor =
                ArgumentCaptor.forClass(tech.cwvermaak.intellisso.model.AuditEvent.AuditEventBuilder.class);
        verify(auditService).log(captor.capture());
        var built = captor.getValue().build();
        assertThat(built.getEventType()).isEqualTo(RefreshTokenService.AUDIT_REFRESH_REUSE);
        assertThat(built.getOutcome())
                .isEqualTo(tech.cwvermaak.intellisso.model.AuditEvent.Outcome.DENIED);
    }

    @Test
    @DisplayName("expired tokens are rejected without triggering reuse detection")
    void expired_rejectedCleanly() {
        String hash = RefreshTokenService.hash("old-raw");
        RefreshToken expired = RefreshToken.builder()
                .id(100L)
                .user(user)
                .tenant(user.getTenant())
                .familyId(UUID.randomUUID())
                .tokenHash(hash)
                .issuedAt(LocalDateTime.now().minusDays(30))
                .expiresAt(LocalDateTime.now().minusDays(1))
                .build();
        when(repo.findByTokenHash(hash)).thenReturn(Optional.of(expired));

        assertThatThrownBy(() -> service.rotate("old-raw", "1.2.3.4", "ua"))
                .isInstanceOf(BadCredentialsException.class)
                .hasMessageContaining("expired");

        verify(repo, never()).revokeFamily(any(), any(), anyString());
    }

    @Test
    @DisplayName("unknown tokens are rejected without touching the DB beyond the lookup")
    void unknownToken_rejected() {
        when(repo.findByTokenHash(anyString())).thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.rotate("nope", "1.2.3.4", "ua"))
                .isInstanceOf(BadCredentialsException.class);
    }

    @Test
    @DisplayName("revokeAllForUser delegates to the repo with a reason label")
    void revokeAllForUser_delegates() {
        when(repo.revokeAllForUser(eq(42L), any(), eq("user_logout_all"))).thenReturn(3);

        int revoked = service.revokeAllForUser(user, "user_logout_all");

        assertThat(revoked).isEqualTo(3);
    }
}
