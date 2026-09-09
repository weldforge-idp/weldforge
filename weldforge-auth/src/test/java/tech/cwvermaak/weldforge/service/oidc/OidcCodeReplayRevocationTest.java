package tech.cwvermaak.weldforge.service.oidc;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import tech.cwvermaak.weldforge.model.OAuthAuthorizationCode;
import tech.cwvermaak.weldforge.model.OidcClient;
import tech.cwvermaak.weldforge.model.Tenant;
import tech.cwvermaak.weldforge.model.User;
import tech.cwvermaak.weldforge.repository.MfaFactorRepository;
import tech.cwvermaak.weldforge.repository.OAuthAuthorizationCodeRepository;
import tech.cwvermaak.weldforge.repository.OidcClientRepository;
import tech.cwvermaak.weldforge.service.TenantMfaPolicyService;
import tech.cwvermaak.weldforge.service.audit.AuditService;
import tech.cwvermaak.weldforge.service.security.RefreshTokenFamilyRevoker;

import java.time.LocalDateTime;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * CONF-1.2 — a replayed authorization code must revoke what it produced
 * (RFC 6749 §4.1.2).
 *
 * <p>Rejecting the second exchange was only the visible half. The other half is
 * what a replay <em>means</em>: two parties presented the same code, so it left
 * the legitimate client's control. Whoever exchanged it first is holding live
 * tokens — and if that was the attacker, the victim gets no signal at all,
 * because from their side the login simply worked.
 *
 * <p>The codebase already treats a family as the unit of revocation for this
 * class of event; refresh reuse detection does exactly this. A replayed code is
 * the same signal one hop earlier.
 */
class OidcCodeReplayRevocationTest {

    private OidcAuthorizationService service;
    private OAuthAuthorizationCodeRepository codeRepository;
    private RefreshTokenFamilyRevoker familyRevoker;

    private Tenant leap;
    private OidcClient portal;
    private final UUID familyId = UUID.randomUUID();

    @BeforeEach
    void setUp() {
        codeRepository = mock(OAuthAuthorizationCodeRepository.class);
        familyRevoker = mock(RefreshTokenFamilyRevoker.class);

        service = new OidcAuthorizationService(
                mock(OidcClientRepository.class),
                codeRepository,
                mock(AuditService.class),
                new io.micrometer.core.instrument.simple.SimpleMeterRegistry(),
                familyRevoker,
                mock(MfaFactorRepository.class),
                mock(TenantMfaPolicyService.class));

        leap = Tenant.builder().id(1L).slug("leap").name("Leap").build();
        portal = OidcClient.builder().id(10L).tenant(leap).clientId("portal")
                .clientSecret("secret").publicClient(false).build();
    }

    private void usedCodeWithFamily(UUID family) {
        OAuthAuthorizationCode row = OAuthAuthorizationCode.builder()
                .id(99L)
                .codeHash(OidcAuthorizationService.sha256("the-code"))
                .client(portal)
                .tenant(leap)
                .user(User.builder().id(42L).tenant(leap).email("a@leap.test").build())
                .redirectUri("https://rp.example.com/cb")
                .scopes("openid email")
                .issuedFamilyId(family)
                .usedAt(LocalDateTime.now().minusMinutes(1))
                .expiresAt(LocalDateTime.now().plusMinutes(4))
                .build();
        when(codeRepository.findByCodeHash(any())).thenReturn(Optional.of(row));
    }

    private void replay() {
        service.exchangeCode(leap, new OidcAuthorizationService.CodeExchangeRequest(
                "the-code", "portal", "secret", "https://rp.example.com/cb", null));
    }

    @Test
    @DisplayName("Replaying a code revokes the family the first exchange produced")
    void replay_revokes_the_family() {
        usedCodeWithFamily(familyId);

        assertThatThrownBy(this::replay)
                .isInstanceOf(OidcAuthorizationException.class)
                .hasMessageContaining("already used");

        verify(familyRevoker).revoke(eq(familyId), eq("code_replay_detected"));
    }

    @Test
    @DisplayName("A replayed code that produced no family is still refused")
    void replay_without_a_family_is_still_refused() {
        // Legitimate: the client held no refresh_token grant, or the row
        // predates V50. Nothing extra to revoke, and that is not an error --
        // but the replay must still be rejected.
        usedCodeWithFamily(null);

        assertThatThrownBy(this::replay)
                .isInstanceOf(OidcAuthorizationException.class)
                .hasMessageContaining("already used");

        verify(familyRevoker, never()).revoke(any(), any());
    }

    @Test
    @DisplayName("A first, legitimate exchange revokes nothing")
    void first_exchange_revokes_nothing() {
        OAuthAuthorizationCode fresh = OAuthAuthorizationCode.builder()
                .id(99L)
                .codeHash(OidcAuthorizationService.sha256("the-code"))
                .client(portal)
                .tenant(leap)
                .user(User.builder().id(42L).tenant(leap).email("a@leap.test").build())
                .redirectUri("https://rp.example.com/cb")
                .scopes("openid email")
                .expiresAt(LocalDateTime.now().plusMinutes(4))
                .build();
        when(codeRepository.findByCodeHash(any())).thenReturn(Optional.of(fresh));

        replay();

        verify(familyRevoker, never()).revoke(any(), any());
    }
}
