package tech.cwvermaak.weldforge.service.oidc;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import tech.cwvermaak.weldforge.model.OidcClient;
import tech.cwvermaak.weldforge.model.RefreshToken;
import tech.cwvermaak.weldforge.model.Tenant;
import tech.cwvermaak.weldforge.model.User;
import tech.cwvermaak.weldforge.repository.RefreshTokenRepository;
import tech.cwvermaak.weldforge.repository.RevokedOidcTokenRepository;
import tech.cwvermaak.weldforge.service.audit.AuditService;
import tech.cwvermaak.weldforge.service.security.RefreshTokenFamilyRevoker;
import tech.cwvermaak.weldforge.service.security.RefreshTokenService;

import java.util.Optional;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * CONF-6.3 — {@code /oauth2/revoke} must actually revoke a refresh token.
 *
 * <p>Before this, an opaque refresh token failed to parse as a tenant-signed
 * JWT, fell into the catch block, logged at debug and returned. RFC 7009
 * mandates 200 either way, so the caller was told the token was dead and it
 * wasn't — a relying party ending a user's session got a success response for
 * nothing. That is worse than an error, because an error would be retried.
 *
 * <p>The negative cases matter as much as the positive one: revocation must not
 * become a way to terminate someone else's sessions, and must not become an
 * oracle for which tokens exist.
 */
class OidcRefreshRevocationTest {

    private OidcRevocationService service;
    private RefreshTokenRepository refreshTokenRepository;
    private RefreshTokenFamilyRevoker familyRevoker;

    private Tenant leap;
    private Tenant other;
    private OidcClient portal;
    private OidcClient rival;

    private static final String RAW = "opaque-refresh-token-value";
    private final UUID familyId = UUID.randomUUID();

    @BeforeEach
    void setUp() {
        refreshTokenRepository = mock(RefreshTokenRepository.class);
        familyRevoker = mock(RefreshTokenFamilyRevoker.class);

        service = new OidcRevocationService(
                mock(TenantSigningKeyService.class),
                mock(RevokedOidcTokenRepository.class),
                mock(AuditService.class),
                refreshTokenRepository,
                familyRevoker);

        leap = Tenant.builder().id(1L).slug("leap").name("Leap").build();
        other = Tenant.builder().id(2L).slug("other").name("Other").build();
        portal = OidcClient.builder().id(10L).tenant(leap).clientId("portal").build();
        rival = OidcClient.builder().id(11L).tenant(leap).clientId("rival").build();
    }

    private void storedTokenBelongingTo(Tenant tenant, OidcClient client) {
        RefreshToken row = RefreshToken.builder()
                .id(500L)
                .user(User.builder().id(42L).tenant(tenant).email("a@leap.test").build())
                .tenant(tenant)
                .client(client)
                .familyId(familyId)
                .build();
        when(refreshTokenRepository.findByTokenHash(RefreshTokenService.hash(RAW)))
                .thenReturn(Optional.of(row));
    }

    @Test
    @DisplayName("Revoking a refresh token kills its whole family")
    void revokes_the_family() {
        storedTokenBelongingTo(leap, portal);

        service.revoke(RAW, leap, portal, "https://sso.weldforge.org/t/leap");

        // The family, not just the presented token: rotation means a successor
        // may already exist, and revoking only what was handed in would leave
        // the session alive, which is not what "revoke this" means.
        verify(familyRevoker).revoke(eq(familyId), eq("client_request"));
    }

    @Test
    @DisplayName("A client cannot revoke another client's refresh token")
    void refuses_another_clients_token() {
        storedTokenBelongingTo(leap, portal);

        service.revoke(RAW, leap, rival, "https://sso.weldforge.org/t/leap");

        // Otherwise any client holding a token hash could terminate another
        // client's sessions -- a cleanup endpoint turned into a DoS primitive.
        verify(familyRevoker, never()).revoke(any(), any());
    }

    @Test
    @DisplayName("A token from another tenant is not revocable here")
    void refuses_cross_tenant_token() {
        storedTokenBelongingTo(other, portal);

        service.revoke(RAW, leap, portal, "https://sso.weldforge.org/t/leap");

        verify(familyRevoker, never()).revoke(any(), any());
    }

    @Test
    @DisplayName("An unknown token is silently accepted, revealing nothing")
    void unknown_token_is_silent() {
        when(refreshTokenRepository.findByTokenHash(any())).thenReturn(Optional.empty());

        // RFC 7009 §2.2 requires 200 for an unknown token so the endpoint
        // cannot be used to probe which tokens exist. No throw, no revoke.
        service.revoke(RAW, leap, portal, "https://sso.weldforge.org/t/leap");

        verify(familyRevoker, never()).revoke(any(), any());
    }

    @Test
    @DisplayName("A null or blank token is a no-op")
    void blank_token_is_a_noop() {
        service.revoke(null, leap, portal, "https://sso.weldforge.org/t/leap");
        service.revoke("  ", leap, portal, "https://sso.weldforge.org/t/leap");

        verify(familyRevoker, never()).revoke(any(), any());
    }
}
