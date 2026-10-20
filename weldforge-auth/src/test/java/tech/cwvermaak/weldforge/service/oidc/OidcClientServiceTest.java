package tech.cwvermaak.weldforge.service.oidc;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import tech.cwvermaak.weldforge.config.tenant.TenantAccessor;
import tech.cwvermaak.weldforge.model.Tenant;
import tech.cwvermaak.weldforge.model.dto.OidcClientDto;
import tech.cwvermaak.weldforge.repository.OidcClientRepository;

import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

/**
 * B-OIDC-4: redirect_uri validation at client registration (RFC 9700 / RFC 8252).
 */
class OidcClientServiceTest {

    private TenantAccessor tenantAccessor;
    private OidcClientRepository repository;
    private OidcClientService service;
    private tech.cwvermaak.weldforge.service.audit.AuditService auditService;

    @BeforeEach
    void setUp() {
        tenantAccessor = mock(TenantAccessor.class);
        repository = mock(OidcClientRepository.class);
        auditService = mock(tech.cwvermaak.weldforge.service.audit.AuditService.class);
        service = new OidcClientService(tenantAccessor, repository, auditService, new AccessTokenLifetime(3600L));
        when(tenantAccessor.requireTenant()).thenReturn(Tenant.builder().id(1L).slug("acme").name("Acme").build());
        when(repository.findByTenantIdAndClientId(anyLong(), anyString())).thenReturn(Optional.empty());
        when(repository.save(any())).thenAnswer(inv -> inv.getArgument(0));
    }

    private OidcClientDto dto(String redirectUri) {
        return OidcClientDto.builder()
                .name("app")
                .redirectUris(List.of(redirectUri))
                .scopes(List.of("openid"))
                .grantTypes(List.of("authorization_code"))
                .build();
    }

    @Test
    @DisplayName("accepts an https redirect_uri and a loopback http one")
    void acceptsValid() {
        assertThatCode(() -> service.create(dto("https://app.acme.test/cb"))).doesNotThrowAnyException();
        assertThatCode(() -> service.create(dto("http://localhost:3000/cb"))).doesNotThrowAnyException();
        assertThatCode(() -> service.create(dto("com.acme.app:/oauth2redirect"))).doesNotThrowAnyException();
    }

    @Test
    @DisplayName("rejects plain http to a non-loopback host")
    void rejectsHttpNonLoopback() {
        assertThatThrownBy(() -> service.create(dto("http://evil.example.com/cb")))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("https");
        verify(repository, never()).save(any());
    }

    @Test
    @DisplayName("rejects a redirect_uri carrying a fragment")
    void rejectsFragment() {
        assertThatThrownBy(() -> service.create(dto("https://app.acme.test/cb#frag")))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("fragment");
    }

    @Test
    @DisplayName("rejects a relative (non-absolute) redirect_uri")
    void rejectsRelative() {
        assertThatThrownBy(() -> service.create(dto("/callback")))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("absolute");
    }

    // ---- audit (2026-09-11) ------------------------------------------

    @Test
    @DisplayName("create is audited with the tenant it landed in")
    void createIsAudited() {
        OidcClientDto in = dto("https://app.acme.test/cb");
        in.setClientId("keycrypt");

        service.create(in);

        verify(auditService).recordAdmin(eq("oidc.client.create"), isNull(), eq("oidc_client"), eq("keycrypt"),
                argThat(m -> "acme".equals(m.get("tenant"))));
    }

    @Test
    @DisplayName("delete is audited with the tenant it was removed from")
    void deleteIsAudited() {
        tech.cwvermaak.weldforge.model.OidcClient c = tech.cwvermaak.weldforge.model.OidcClient.builder()
                .id(5L).clientId("stray").name("Stray")
                .tenant(Tenant.builder().id(1L).slug("default").name("Default").build()).build();
        when(tenantAccessor.requireTenantId()).thenReturn(1L);
        when(repository.findByIdAndTenantId(5L, 1L)).thenReturn(Optional.of(c));

        service.delete(5L);

        verify(repository).delete(c);
        verify(auditService).recordAdmin(eq("oidc.client.delete"), isNull(), eq("oidc_client"), eq("stray"),
                argThat(m -> "default".equals(m.get("tenant"))));
    }

    /**
     * A client may shorten its access tokens, never lengthen them.
     *
     * <p>The tenant in this suite has no access_ttl_ms of its own, so the
     * ceiling is the deployment default the service was built with: 3600s.
     */
    @org.junit.jupiter.api.Nested
    @DisplayName("accessTokenTtlSeconds")
    class AccessTokenTtl {

        private Tenant acme() {
            return Tenant.builder().id(1L).slug("acme").name("Acme").build();
        }

        private OidcClientDto dtoWithTtl(Integer seconds) {
            return OidcClientDto.builder()
                    .name("app")
                    .redirectUris(List.of("https://app.acme.test/cb"))
                    .scopes(List.of("openid"))
                    .grantTypes(List.of("authorization_code"))
                    .accessTokenTtlSeconds(seconds)
                    .build();
        }

        @Test
        @DisplayName("a value below the tenant's ceiling is accepted and read back")
        void belowCeiling() {
            assertThat(service.create(dtoWithTtl(1800)).getAccessTokenTtlSeconds()).isEqualTo(1800);
        }

        @Test
        @DisplayName("omitting it leaves the client inheriting, not pinned to the default")
        void omittedInherits() {
            assertThat(service.create(dtoWithTtl(null)).getAccessTokenTtlSeconds()).isNull();
        }

        @Test
        @DisplayName("exactly the ceiling is accepted")
        void atCeiling() {
            assertThat(service.create(dtoWithTtl(3600)).getAccessTokenTtlSeconds()).isEqualTo(3600);
        }

        @Test
        @DisplayName("above the ceiling is refused, and the message names the ceiling")
        void aboveCeiling() {
            assertThatThrownBy(() -> service.create(dtoWithTtl(86_400)))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("3600")
                    .hasMessageContaining("shorten");
            verify(repository, never()).save(any());
        }

        @Test
        @DisplayName("zero and negative are refused rather than read as 'unset'")
        void zeroOrNegative() {
            assertThatThrownBy(() -> service.create(dtoWithTtl(0)))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("must be positive");
            assertThatThrownBy(() -> service.create(dtoWithTtl(-1)))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("must be positive");
        }

        /**
         * The reason the ceiling exists at all. This path has no admin
         * session: without the cap a client registering itself could ask for,
         * and be given, a thirty-day access token.
         */
        @Test
        @DisplayName("a self-registering client cannot grant itself a long-lived token")
        void dynamicRegistrationIsCappedToo() {
            assertThatThrownBy(() -> service.createForDynamicRegistration(acme(), dtoWithTtl(2_592_000)))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("shorten");
            verify(repository, never()).save(any());
        }

        @Test
        @DisplayName("a self-registering client may still shorten its own tokens")
        void dynamicRegistrationMayShorten() {
            assertThat(service.createForDynamicRegistration(acme(), dtoWithTtl(300)).getAccessTokenTtlSeconds())
                    .isEqualTo(300);
        }

        @Test
        @DisplayName("an update is held to the same ceiling as a registration")
        void updateIsCapped() {
            Tenant acme = Tenant.builder().id(1L).slug("acme").name("Acme").build();
            tech.cwvermaak.weldforge.model.OidcClient stored =
                    tech.cwvermaak.weldforge.model.OidcClient.builder()
                            .id(5L).tenant(acme).clientId("acme-app")
                            .redirectUris("https://app.acme.test/cb")
                            .scopes("openid").grantTypes("authorization_code")
                            .build();
            when(repository.findById(5L)).thenReturn(Optional.of(stored));

            assertThatThrownBy(() -> service.updateById(5L, dtoWithTtl(86_400)))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("shorten");
            assertThat(stored.getAccessTokenTtlSeconds()).isNull();

            assertThat(service.updateById(5L, dtoWithTtl(900)).getAccessTokenTtlSeconds())
                    .isEqualTo(900);
        }
    }
}
