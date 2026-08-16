package tech.cwvermaak.weldforge.service.security;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.BadCredentialsException;
import tech.cwvermaak.weldforge.model.OidcClient;
import tech.cwvermaak.weldforge.model.RefreshToken;
import tech.cwvermaak.weldforge.model.Tenant;
import tech.cwvermaak.weldforge.model.User;
import tech.cwvermaak.weldforge.repository.RefreshTokenRepository;
import tech.cwvermaak.weldforge.service.audit.AuditService;

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
 * Client binding for OIDC refresh tokens (RFC 6749 §6, §10.4).
 *
 * A refresh token is a bearer credential issued to one relying party. If any
 * client could spend it, a client that legitimately holds tokens for its own
 * users could mint access tokens in another client's name — so a mismatch is
 * treated exactly like reuse and kills the family.
 */
class RefreshTokenClientBindingTest {

    private RefreshTokenRepository repo;
    private AuditService auditService;
    private RefreshTokenFamilyRevoker revoker;
    private RefreshTokenService service;
    private User user;
    private OidcClient dashboard;
    private OidcClient otherApp;

    @BeforeEach
    void setUp() {
        repo = mock(RefreshTokenRepository.class);
        auditService = mock(AuditService.class);
        RefreshTokenProperties props = new RefreshTokenProperties();
        props.setLifetimeDays(7);
        revoker = mock(RefreshTokenFamilyRevoker.class);
        service = new RefreshTokenService(repo, revoker, props, auditService);

        Tenant t = Tenant.builder().id(1L).slug("acme").name("Acme").build();
        user = User.builder().id(42L).tenant(t).email("alice@acme.test").build();
        dashboard = OidcClient.builder().id(7L).clientId("dashboard").build();
        otherApp = OidcClient.builder().id(9L).clientId("other-app").build();

        AtomicLong idSeq = new AtomicLong(1);
        when(repo.save(any(RefreshToken.class))).thenAnswer(inv -> {
            RefreshToken r = inv.getArgument(0);
            if (r.getId() == null) r.setId(idSeq.getAndIncrement());
            return r;
        });
    }

    private RefreshToken existingFor(OidcClient client, String rawToken) {
        RefreshToken row = RefreshToken.builder()
                .id(100L)
                .user(user)
                .tenant(user.getTenant())
                .client(client)
                .familyId(UUID.randomUUID())
                .tokenHash(RefreshTokenService.hash(rawToken))
                .issuedAt(LocalDateTime.now().minusHours(1))
                .expiresAt(LocalDateTime.now().plusDays(6))
                .build();
        when(repo.findByTokenHash(RefreshTokenService.hash(rawToken)))
                .thenReturn(Optional.of(row));
        return row;
    }

    @Test
    @DisplayName("a token issued through OIDC records the client that got it")
    void issueNewForClient_bindsToClient() {
        RefreshTokenService.Issued issued =
                service.issueNewForClient(user, dashboard, "1.2.3.4", "ua");

        assertThat(issued.row().getClient()).isSameAs(dashboard);
        assertThat(issued.rawToken()).isNotBlank();
        assertThat(issued.row().getTokenHash()).isNotEqualTo(issued.rawToken());
    }

    @Test
    @DisplayName("the issuing client can rotate, and the successor keeps the binding")
    void rotateForClient_succeedsForOwner() {
        RefreshToken existing = existingFor(dashboard, "raw-token");

        RefreshTokenService.Issued successor =
                service.rotateForClient("raw-token", dashboard, "1.2.3.4", "ua");

        assertThat(existing.getUsedAt()).isNotNull();
        assertThat(successor.row().getFamilyId()).isEqualTo(existing.getFamilyId());
        assertThat(successor.row().getClient()).isSameAs(dashboard);
        assertThat(successor.rawToken()).isNotEqualTo("raw-token");
    }

    @Test
    @DisplayName("a different client cannot spend the token, and the family is revoked")
    void rotateForClient_rejectsOtherClientAndKillsFamily() {
        RefreshToken existing = existingFor(dashboard, "raw-token");

        assertThatThrownBy(() -> service.rotateForClient("raw-token", otherApp, "1.2.3.4", "ua"))
                .isInstanceOf(BadCredentialsException.class);

        verify(revoker).revoke(existing.getFamilyId(), "client_mismatch");
        verify(auditService).log(any());
        // The rightful holder's token must not have been quietly consumed.
        assertThat(existing.getUsedAt()).isNull();
        verify(repo, never()).save(any(RefreshToken.class));
    }

    @Test
    @DisplayName("a session-flow token cannot be spent at the OIDC token endpoint")
    void rotateForClient_rejectsUnboundToken() {
        RefreshToken existing = existingFor(null, "session-raw");

        assertThatThrownBy(() -> service.rotateForClient("session-raw", dashboard, "1.2.3.4", "ua"))
                .isInstanceOf(BadCredentialsException.class);

        verify(revoker).revoke(existing.getFamilyId(), "client_mismatch");
    }

    @Test
    @DisplayName("reuse detection still applies once the client matches")
    void rotateForClient_reuseStillKillsFamily() {
        RefreshToken existing = existingFor(dashboard, "raw-token");
        existing.setUsedAt(LocalDateTime.now().minusMinutes(5));

        assertThatThrownBy(() -> service.rotateForClient("raw-token", dashboard, "1.2.3.4", "ua"))
                .isInstanceOf(BadCredentialsException.class);

        verify(revoker).revoke(existing.getFamilyId(), "reuse_detected");
    }

    @Test
    @DisplayName("an expired token is refused")
    void rotateForClient_refusesExpired() {
        RefreshToken existing = existingFor(dashboard, "raw-token");
        existing.setExpiresAt(LocalDateTime.now().minusMinutes(1));

        assertThatThrownBy(() -> service.rotateForClient("raw-token", dashboard, "1.2.3.4", "ua"))
                .isInstanceOf(BadCredentialsException.class);
    }

    @Test
    @DisplayName("a missing client or unknown token is refused rather than NPE'ing")
    void rotateForClient_refusesMissingInputs() {
        assertThatThrownBy(() -> service.rotateForClient("raw", null, null, null))
                .isInstanceOf(BadCredentialsException.class);

        when(repo.findByTokenHash(anyString())).thenReturn(Optional.empty());
        assertThatThrownBy(() -> service.rotateForClient("nope", dashboard, null, null))
                .isInstanceOf(BadCredentialsException.class);
    }
}
