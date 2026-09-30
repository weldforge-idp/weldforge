package tech.cwvermaak.weldforge.service.oidc;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import tech.cwvermaak.weldforge.config.tenant.TenantAccessor;
import tech.cwvermaak.weldforge.model.OidcClient;
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
import static org.mockito.Mockito.*;

/**
 * Editing an OIDC client in place.
 *
 * <p>Before this existed the only way to correct a registration was to delete
 * and recreate it, which mints a new {@code client_secret} and breaks every
 * deployed consumer. Two production clients were left misconfigured rather
 * than pay that cost — {@code keycrypt-web} with no {@code webOrigins} (its
 * sign-in was inert for two days) and then with no
 * {@code post_logout_redirect_uris} (its sign-out answered a bare 400).
 *
 * <p>The cases that must be REFUSED matter as much as the ones that work:
 * an update that can silently change a client's identity or authentication
 * model is worse than no update endpoint at all.
 */
@DisplayName("OIDC client update")
class OidcClientUpdateTest {

    private static final Tenant TENANT =
            Tenant.builder().id(1L).slug("acme").name("Acme").build();

    private TenantAccessor tenantAccessor;
    private OidcClientRepository repository;
    private OidcClientService service;
    private OidcClient existing;

    @BeforeEach
    void setUp() {
        tenantAccessor = mock(TenantAccessor.class);
        repository = mock(OidcClientRepository.class);
        var auditService = mock(tech.cwvermaak.weldforge.service.audit.AuditService.class);
        service = new OidcClientService(tenantAccessor, repository, auditService);

        when(tenantAccessor.requireTenant()).thenReturn(TENANT);
        when(tenantAccessor.requireTenantId()).thenReturn(1L);

        existing = OidcClient.builder()
                .id(7L)
                .tenant(TENANT)
                .clientId("keycrypt-web")
                .name("KeyCrypt")
                .redirectUris("https://keycrypt.example.test/callback")
                .postLogoutRedirectUris("")
                .webOrigins("https://keycrypt.example.test")
                .scopes("openid profile email")
                .grantTypes("authorization_code refresh_token")
                .publicClient(true)
                .requirePkce(true)
                .requireMfa(false)
                .maxAuthenticationAgeSeconds(0)
                .tokenEndpointAuthMethod("none")
                .build();

        when(repository.findByIdAndTenantId(anyLong(), anyLong())).thenReturn(Optional.of(existing));
    }

    @Nested
    @DisplayName("allowed")
    class Allowed {

        @Test
        @DisplayName("registers a post-logout redirect URI — the keycrypt-web case")
        void adds_post_logout_uri() {
            OidcClientDto out = service.update(7L, OidcClientDto.builder()
                    .postLogoutRedirectUris(List.of("https://keycrypt.example.test/callback"))
                    .build());

            assertThat(out.getPostLogoutRedirectUris())
                    .containsExactly("https://keycrypt.example.test/callback");
            // Untouched fields survive a partial update.
            assertThat(out.getRedirectUris()).containsExactly("https://keycrypt.example.test/callback");
            assertThat(out.getScopes()).containsExactly("openid", "profile", "email");
        }

        @Test
        @DisplayName("sets a per-client refresh TTL — the Clepsydra 14-day case")
        void sets_refresh_ttl() {
            OidcClientDto out = service.update(7L, OidcClientDto.builder()
                    .refreshTokenTtlSeconds(1_209_600)
                    .build());

            assertThat(out.getRefreshTokenTtlSeconds()).isEqualTo(1_209_600);
        }

        @Test
        @DisplayName("null fields are left alone, so a partial update is safe")
        void partial_update_leaves_the_rest() {
            service.update(7L, OidcClientDto.builder().name("KeyCrypt Web").build());

            assertThat(existing.getName()).isEqualTo("KeyCrypt Web");
            assertThat(existing.getRedirectUriList())
                    .containsExactly("https://keycrypt.example.test/callback");
            assertThat(existing.getWebOriginList())
                    .containsExactly("https://keycrypt.example.test");
        }

        @Test
        @DisplayName("a native client may clear its web origins")
        void native_client_may_clear_origins() {
            existing.setRedirectUris("http://127.0.0.1/callback");
            assertThatCode(() -> service.update(7L, OidcClientDto.builder()
                    .webOrigins(List.of())
                    .build())).doesNotThrowAnyException();
        }
    }

    @Nested
    @DisplayName("refused")
    class Refused {

        @Test
        @DisplayName("clearing a browser client's origins — same failure as registering without them")
        void cannot_strip_origins_from_a_browser_client() {
            assertThatThrownBy(() -> service.update(7L, OidcClientDto.builder()
                    .webOrigins(List.of())
                    .build()))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("webOrigins is required");
        }

        @Test
        @DisplayName("changing clientId — it is the aud of every token already issued")
        void cannot_change_client_id() {
            assertThatThrownBy(() -> service.update(7L, OidcClientDto.builder()
                    .clientId("keycrypt-web-v2")
                    .build()))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("clientId cannot be changed");
        }

        @Test
        @DisplayName("flipping public to confidential — it would hand out an unusable secret")
        void cannot_change_public_flag() {
            assertThatThrownBy(() -> service.update(7L, OidcClientDto.builder()
                    .publicClient(false)
                    .build()))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("publicClient cannot be changed");
        }

        @Test
        @DisplayName("setting a secret here — rotation has its own endpoint")
        void cannot_set_secret() {
            assertThatThrownBy(() -> service.update(7L, OidcClientDto.builder()
                    .clientSecret("wfs_hunter2")
                    .build()))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("rotate-secret");
        }

        @Test
        @DisplayName("a non-positive TTL, which would mean 'already expired' rather than 'inherit'")
        void rejects_non_positive_ttl() {
            assertThatThrownBy(() -> service.update(7L, OidcClientDto.builder()
                    .refreshTokenTtlSeconds(0)
                    .build()))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("must be positive");
        }

        @Test
        @DisplayName("an invalid redirect URI is caught on update, not only on create")
        void validates_redirect_uris() {
            assertThatThrownBy(() -> service.update(7L, OidcClientDto.builder()
                    .redirectUris(List.of("http://not-loopback.example.test/cb"))
                    .build()))
                    .isInstanceOf(IllegalArgumentException.class);
        }

        @Test
        @DisplayName("resending the SAME clientId is fine — it is a no-op, not a rename")
        void unchanged_client_id_is_accepted() {
            assertThatCode(() -> service.update(7L, OidcClientDto.builder()
                    .clientId("keycrypt-web")
                    .name("Renamed")
                    .build())).doesNotThrowAnyException();
            assertThat(existing.getName()).isEqualTo("Renamed");
        }
    }

    @Nested
    @DisplayName("create")
    class Create {

        @Test
        @DisplayName("persists a refresh TTL given at registration")
        void create_persists_ttl() {
            // It was accepted and dropped: the field was on the DTO and in the
            // update path, so a caller sending it at create got a 200 and a
            // client that inherited the default anyway.
            when(repository.findByTenantIdAndClientId(anyLong(), any())).thenReturn(Optional.empty());
            when(repository.save(any())).thenAnswer(inv -> inv.getArgument(0));

            OidcClientDto out = service.create(OidcClientDto.builder()
                    .name("clepsydra")
                    .redirectUris(List.of("http://127.0.0.1/callback"))
                    .scopes(List.of("openid"))
                    .grantTypes(List.of("authorization_code", "refresh_token"))
                    .publicClient(true)
                    .refreshTokenTtlSeconds(1_209_600)
                    .build());

            assertThat(out.getRefreshTokenTtlSeconds()).isEqualTo(1_209_600);
        }

        @Test
        @DisplayName("omitting it leaves the client inheriting")
        void create_without_ttl_inherits() {
            when(repository.findByTenantIdAndClientId(anyLong(), any())).thenReturn(Optional.empty());
            when(repository.save(any())).thenAnswer(inv -> inv.getArgument(0));

            OidcClientDto out = service.create(OidcClientDto.builder()
                    .name("plain")
                    .redirectUris(List.of("http://127.0.0.1/callback"))
                    .scopes(List.of("openid"))
                    .grantTypes(List.of("authorization_code"))
                    .publicClient(true)
                    .build());

            assertThat(out.getRefreshTokenTtlSeconds()).isNull();
        }

        @Test
        @DisplayName("a non-positive TTL is refused at create, as it is on update")
        void create_rejects_non_positive_ttl() {
            when(repository.findByTenantIdAndClientId(anyLong(), any())).thenReturn(Optional.empty());

            assertThatThrownBy(() -> service.create(OidcClientDto.builder()
                    .name("bad")
                    .redirectUris(List.of("http://127.0.0.1/callback"))
                    .scopes(List.of("openid"))
                    .grantTypes(List.of("authorization_code"))
                    .publicClient(true)
                    .refreshTokenTtlSeconds(0)
                    .build()))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("must be positive");
        }
    }
}
