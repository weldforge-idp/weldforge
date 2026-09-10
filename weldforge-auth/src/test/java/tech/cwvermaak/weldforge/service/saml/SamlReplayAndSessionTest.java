package tech.cwvermaak.weldforge.service.saml;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.dao.DataIntegrityViolationException;
import tech.cwvermaak.weldforge.config.tenant.PublicHostProperties;
import tech.cwvermaak.weldforge.model.AuditEvent;
import tech.cwvermaak.weldforge.model.RefreshToken;
import tech.cwvermaak.weldforge.model.SamlRequestReplay;
import tech.cwvermaak.weldforge.model.SamlServiceProvider;
import tech.cwvermaak.weldforge.model.Tenant;
import tech.cwvermaak.weldforge.model.User;
import tech.cwvermaak.weldforge.repository.RefreshTokenRepository;
import tech.cwvermaak.weldforge.repository.SamlRequestReplayRepository;
import tech.cwvermaak.weldforge.service.AuthService;
import tech.cwvermaak.weldforge.service.audit.AuditService;
import tech.cwvermaak.weldforge.service.security.RefreshTokenFamilyRevoker;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

/**
 * The branch logic behind the Sprint 5 follow-up: request freshness and
 * replay (CONF-5.3), and session-scoped SAML logout (CONF-5.2).
 */
class SamlReplayAndSessionTest {

    private final Tenant acme = Tenant.builder().id(1L).slug("acme").name("Acme").build();
    private final SamlServiceProvider sp = SamlServiceProvider.builder()
            .id(10L).tenant(acme).entityId("https://sp.acme.test/saml").build();
    private final User alice = User.builder().id(7L).tenant(acme).email("alice@acme.test").build();

    private SamlRequestReplayRepository replayRepository;
    private AuditService auditService;
    private final List<AuditEvent> audited = new ArrayList<>();
    private SamlIdpService idpService;

    @BeforeEach
    void setUp() {
        replayRepository = mock(SamlRequestReplayRepository.class);
        auditService = mock(AuditService.class);
        doAnswer(inv -> {
            AuditEvent.AuditEventBuilder b = inv.getArgument(0);
            audited.add(b.build());
            return null;
        }).when(auditService).log(any());
        idpService = new SamlIdpService(null, null, null, null, null, auditService,
                null, new PublicHostProperties(), replayRepository);
    }

    // ---- CONF-5.3: freshness and replay ------------------------------

    @Test
    @DisplayName("The replay window outlasts the oldest request the freshness check accepts")
    void retention_covers_freshness_window() {
        // If this ever inverts, a request could be replayed in the gap between
        // its ID being forgotten and its IssueInstant going stale.
        assertThat(SamlIdpService.REPLAY_RETENTION)
                .isGreaterThan(SamlIdpService.AUTHN_REQUEST_MAX_AGE.plus(SamlIdpService.CLOCK_SKEW));
    }

    @Test
    @DisplayName("A fresh, unseen request is recorded with an expiry inside the retention window")
    void fresh_request_is_recorded() {
        idpService.rejectReplayedRequest(acme, sp, "_new", Instant.now());

        verify(replayRepository).saveAndFlush(argThat((SamlRequestReplay r) ->
                "_new".equals(r.getRequestId())
                        && r.getExpiresAt().isAfter(java.time.LocalDateTime.now().plusMinutes(15))));
    }

    @Test
    @DisplayName("A request just inside the clock-skew allowance is still accepted")
    void skew_is_tolerated() {
        Instant slightlyAhead = Instant.now().plus(Duration.ofMinutes(2));
        idpService.rejectReplayedRequest(acme, sp, "_skew", slightlyAhead);

        verify(replayRepository).saveAndFlush(any());
    }

    @Test
    @DisplayName("A stale request is refused before its ID is even looked up")
    void stale_request_refused() {
        Instant old = Instant.now().minus(Duration.ofMinutes(20));

        assertThatThrownBy(() -> idpService.rejectReplayedRequest(acme, sp, "_old", old))
                .isInstanceOf(SamlMessageException.class)
                .hasMessageContaining("too old");
        verify(replayRepository, never()).saveAndFlush(any());
        assertThat(audited).singleElement().satisfies(e -> {
            assertThat(e.getEventType()).isEqualTo("saml.authnrequest.replay");
            assertThat(e.getOutcome()).isEqualTo(AuditEvent.Outcome.DENIED);
        });
    }

    @Test
    @DisplayName("A request seen before is refused")
    void seen_request_refused() {
        when(replayRepository.existsById("_dup")).thenReturn(true);

        assertThatThrownBy(() -> idpService.rejectReplayedRequest(acme, sp, "_dup", Instant.now()))
                .isInstanceOf(SamlMessageException.class)
                .hasMessageContaining("already been processed");
        verify(replayRepository, never()).saveAndFlush(any());
    }

    @Test
    @DisplayName("Two concurrent copies of one request: the loser is refused, not a 500")
    void concurrent_duplicate_refused() {
        // Both copies pass existsById; the primary key is what separates them.
        when(replayRepository.existsById("_race")).thenReturn(false);
        when(replayRepository.saveAndFlush(any()))
                .thenThrow(new DataIntegrityViolationException("duplicate key"));

        assertThatThrownBy(() -> idpService.rejectReplayedRequest(acme, sp, "_race", Instant.now()))
                .isInstanceOf(SamlMessageException.class);
        assertThat(audited).extracting(AuditEvent::getOutcome).containsExactly(AuditEvent.Outcome.DENIED);
    }

    @Test
    @DisplayName("A request with no ID or IssueInstant is let through, as an SP bug rather than an attack")
    void missing_fields_are_tolerated() {
        idpService.rejectReplayedRequest(acme, sp, null, null);

        verify(replayRepository, never()).saveAndFlush(any());
        assertThat(audited).isEmpty();
    }

    // ---- CONF-5.2: session index --------------------------------------

    @Test
    @DisplayName("A session index is stable per session, distinct per SP, and a valid xs:ID")
    void session_index_properties() {
        String sid = UUID.randomUUID().toString();
        SamlServiceProvider other = SamlServiceProvider.builder().entityId("https://other.test").build();

        String a = SamlIdpService.sessionIndexFor(sid, sp);

        assertThat(SamlIdpService.sessionIndexFor(sid, sp)).isEqualTo(a);
        assertThat(SamlIdpService.sessionIndexFor(sid, other)).isNotEqualTo(a);
        assertThat(SamlIdpService.sessionIndexFor(UUID.randomUUID().toString(), sp)).isNotEqualTo(a);
        assertThat(a).matches("_[A-Za-z0-9_-]{22}");
    }

    // ---- CONF-5.2: SP-initiated logout --------------------------------

    private SamlSloService sloService(RefreshTokenRepository refreshTokens,
                                      RefreshTokenFamilyRevoker revoker, AuthService authService) {
        return new SamlSloService(null, auditService, idpService, refreshTokens, revoker, authService);
    }

    private static RefreshToken token(UUID family) {
        return RefreshToken.builder().familyId(family).build();
    }

    @Test
    @DisplayName("Only the named session ends; rotated rows of one family revoke it once")
    void named_session_only() {
        UUID laptop = UUID.randomUUID();
        UUID phone = UUID.randomUUID();
        RefreshTokenRepository refreshTokens = mock(RefreshTokenRepository.class);
        // Two live rows for the laptop family: rotation leaves the used one un-revoked.
        when(refreshTokens.findByUserIdAndRevokedAtIsNull(7L))
                .thenReturn(List.of(token(laptop), token(laptop), token(phone)));
        RefreshTokenFamilyRevoker revoker = mock(RefreshTokenFamilyRevoker.class);
        AuthService authService = mock(AuthService.class);

        SamlSloService.LogoutOutcome outcome = sloService(refreshTokens, revoker, authService)
                .terminateSessions(acme, sp, alice,
                        List.of(SamlIdpService.sessionIndexFor(laptop.toString(), sp)), laptop.toString());

        verify(revoker, times(1)).revoke(laptop, "saml_slo");
        verify(revoker, never()).revoke(eq(phone), anyString());
        verify(authService, never()).logoutAll(any());
        assertThat(outcome.sessionsEnded()).isEqualTo(1);
        assertThat(outcome.currentSessionEnded()).isTrue();
    }

    @Test
    @DisplayName("An index that is not one of the caller's sessions ends nothing")
    void foreign_index_ends_nothing() {
        RefreshTokenRepository refreshTokens = mock(RefreshTokenRepository.class);
        when(refreshTokens.findByUserIdAndRevokedAtIsNull(anyLong()))
                .thenReturn(List.of(token(UUID.randomUUID())));
        RefreshTokenFamilyRevoker revoker = mock(RefreshTokenFamilyRevoker.class);
        AuthService authService = mock(AuthService.class);

        SamlSloService.LogoutOutcome outcome = sloService(refreshTokens, revoker, authService)
                .terminateSessions(acme, sp, alice,
                        List.of(SamlIdpService.sessionIndexFor(UUID.randomUUID().toString(), sp)), null);

        verifyNoInteractions(revoker);
        verify(authService, never()).logoutAll(any());
        assertThat(outcome.sessionsEnded()).isZero();
        assertThat(outcome.currentSessionEnded()).isFalse();
    }

    @Test
    @DisplayName("The same session's index for a different SP does not match")
    void index_for_another_sp_does_not_match() {
        UUID laptop = UUID.randomUUID();
        RefreshTokenRepository refreshTokens = mock(RefreshTokenRepository.class);
        when(refreshTokens.findByUserIdAndRevokedAtIsNull(anyLong())).thenReturn(List.of(token(laptop)));
        RefreshTokenFamilyRevoker revoker = mock(RefreshTokenFamilyRevoker.class);
        SamlServiceProvider other = SamlServiceProvider.builder().id(11L).entityId("https://other.test").build();

        sloService(refreshTokens, revoker, mock(AuthService.class)).terminateSessions(acme, sp, alice,
                List.of(SamlIdpService.sessionIndexFor(laptop.toString(), other)), null);

        verifyNoInteractions(revoker);
    }

    @Test
    @DisplayName("No SessionIndex ends every session of the principal")
    void no_index_ends_everything() {
        RefreshTokenFamilyRevoker revoker = mock(RefreshTokenFamilyRevoker.class);
        AuthService authService = mock(AuthService.class);

        SamlSloService.LogoutOutcome outcome = sloService(mock(RefreshTokenRepository.class), revoker, authService)
                .terminateSessions(acme, sp, alice, List.of(), null);

        verify(authService).logoutAll(alice);
        assertThat(outcome.allSessions()).isTrue();
        assertThat(outcome.currentSessionEnded()).isTrue();
    }

    @Test
    @DisplayName("An IdP-initiated LogoutRequest names the session being ended")
    void idp_logout_request_carries_session_index() {
        String sid = UUID.randomUUID().toString();
        SamlServiceProvider withSlo = SamlServiceProvider.builder().id(12L).tenant(acme)
                .entityId("https://sp.acme.test/saml").sloUrl("https://sp.acme.test/slo")
                .nameIdFormat(SamlIdpService.NAMEID_EMAIL).build();

        String encoded = sloService(mock(RefreshTokenRepository.class), mock(RefreshTokenFamilyRevoker.class),
                mock(AuthService.class)).buildLogoutRequest(acme, alice, withSlo,
                SamlSloService.Binding.POST, sid);
        String xml = new String(java.util.Base64.getDecoder().decode(encoded),
                java.nio.charset.StandardCharsets.UTF_8);

        assertThat(xml).contains("<samlp:SessionIndex>"
                + SamlIdpService.sessionIndexFor(sid, withSlo) + "</samlp:SessionIndex>");
        // SessionIndex must follow NameID in the schema's sequence.
        assertThat(xml.indexOf("SessionIndex")).isGreaterThan(xml.indexOf("NameID"));
    }
}
