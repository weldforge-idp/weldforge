package tech.cwvermaak.weldforge.service.oidc;

import io.jsonwebtoken.Jwts;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;
import tech.cwvermaak.weldforge.model.OidcClient;
import tech.cwvermaak.weldforge.model.Role;
import tech.cwvermaak.weldforge.model.Tenant;
import tech.cwvermaak.weldforge.model.TenantSigningKey;
import tech.cwvermaak.weldforge.model.User;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Contract test for the {@code roles} claim. Asserts that the token issued
 * for a code-exchange flow carries the user's tenant-scoped role and the
 * legacy super-admin flag, deduplicated, so relying parties can drive RBAC
 * straight off the JWT.
 */
@DisplayName("OidcTokenService — roles claim emission")
class OidcTokenServiceRolesClaimTest {

    private OidcTokenService service;
    private TenantSigningKeyService signingKeyService;
    private RSAPrivateKey privateKey;
    private PublicKey publicKey;

    private Tenant tenant;
    private OidcClient client;

    @BeforeEach
    void setUp() throws Exception {
        KeyPair kp = KeyPairGenerator.getInstance("RSA").genKeyPair();
        privateKey = (RSAPrivateKey) kp.getPrivate();
        publicKey = kp.getPublic();

        signingKeyService = mock(TenantSigningKeyService.class);
        TenantSigningKey signingKey = mock(TenantSigningKey.class);
        when(signingKey.getKid()).thenReturn("test-kid");
        when(signingKeyService.getOrCreateActive(any())).thenReturn(signingKey);
        when(signingKeyService.loadPrivateKey(any())).thenReturn(privateKey);

        service = new OidcTokenService(signingKeyService, new SimpleMeterRegistry());
        ReflectionTestUtils.setField(service, "accessTokenSeconds", 3600L);
        ReflectionTestUtils.setField(service, "idTokenSeconds", 3600L);

        tenant = Tenant.builder()
            .id(1L).slug("wellspring").name("Wellspring")
            .accessTtlMs(3_600_000L)
            .build();
        client = OidcClient.builder()
            .id(10L).tenant(tenant).clientId("wellspring-app")
            .build();
    }

    private Map<String, Object> parseClaims(String token) {
        return Jwts.parser()
            .verifyWith(publicKey)
            .build()
            .parseSignedClaims(token)
            .getPayload();
    }

    @Nested
    @DisplayName("Given a user with a tenant-scoped role and the super-admin flag set")
    class SuperAdminAndRole {

        @Test
        @DisplayName("When a code-exchange access token is issued, "
                  + "Then roles claim contains both SUPERADMIN and the role.name, deduplicated")
        void roles_claim_carries_both_and_dedupes() {
            User user = User.builder()
                .id(42L).tenant(tenant)
                .username("info@wellspring.org.za").email("info@wellspring.org.za")
                .role(Role.builder().id(1L).tenant(tenant).name("SUPERADMIN").build())
                .superAdmin(true)
                .build();

            OidcTokenService.IssuedTokens out = service.issueForCodeExchange(
                tenant, client, user, List.of("openid"), "n-1",
                "https://sso.weldforge.org/t/wellspring");

            Map<String, Object> claims = parseClaims(out.accessToken());
            assertThat(claims.get("sub")).isEqualTo("42");
            assertThat(claims.get("email")).isEqualTo("info@wellspring.org.za");
            // Dedup: boolean true + role.name="SUPERADMIN" collapses to one entry.
            @SuppressWarnings("unchecked")
            List<String> roles = (List<String>) claims.get("roles");
            assertThat(roles).containsExactly("SUPERADMIN");
        }
    }

    @Nested
    @DisplayName("Given a regular user with only a tenant-scoped role")
    class RoleOnly {

        @Test
        @DisplayName("Then roles claim contains only the role.name, no SUPERADMIN")
        void only_application_role_emitted() {
            User user = User.builder()
                .id(7L).tenant(tenant)
                .username("alice").email("alice@example.org")
                .role(Role.builder().id(2L).tenant(tenant).name("SITE_ADMIN").build())
                .superAdmin(false)
                .build();

            OidcTokenService.IssuedTokens out = service.issueForCodeExchange(
                tenant, client, user, List.of("openid"), null,
                "https://sso.weldforge.org/t/wellspring");

            @SuppressWarnings("unchecked")
            List<String> roles = (List<String>) parseClaims(out.accessToken()).get("roles");
            assertThat(roles).containsExactly("SITE_ADMIN");
        }
    }

    @Nested
    @DisplayName("Given a user with no role at all")
    class NoRole {

        @Test
        @DisplayName("Then roles claim is an empty array, never null")
        void empty_array_for_roleless_user() {
            User user = User.builder()
                .id(99L).tenant(tenant)
                .username("guest").email("guest@example.org")
                .role(null)
                .superAdmin(false)
                .build();

            OidcTokenService.IssuedTokens out = service.issueForCodeExchange(
                tenant, client, user, List.of("openid"), null,
                "https://sso.weldforge.org/t/wellspring");

            @SuppressWarnings("unchecked")
            List<String> roles = (List<String>) parseClaims(out.accessToken()).get("roles");
            assertThat(roles).isEmpty();
        }
    }

    @Nested
    @DisplayName("Given a client-credentials grant — no end-user")
    class ClientCredentials {

        @Test
        @DisplayName("Then no roles claim is added (machine identity has no app role)")
        void no_roles_for_client_credentials() {
            String token = service.issueForClientCredentials(
                tenant, client, List.of("api.read"),
                "https://sso.weldforge.org/t/wellspring").accessToken();

            Map<String, Object> claims = parseClaims(token);
            assertThat(claims).doesNotContainKey("roles");
            assertThat(claims.get("sub")).isEqualTo("wellspring-app");
        }
    }

    @Nested
    @DisplayName("Given the ID token is also issued for the same exchange")
    class IdToken {

        @Test
        @DisplayName("Then the ID token carries the same roles claim so SPAs can drive UI gating off it")
        void id_token_carries_roles_too() {
            User user = User.builder()
                .id(42L).tenant(tenant)
                .email("info@wellspring.org.za").username("info@wellspring.org.za")
                .role(Role.builder().id(1L).tenant(tenant).name("SUPERADMIN").build())
                .superAdmin(false)
                .build();

            OidcTokenService.IssuedTokens out = service.issueForCodeExchange(
                tenant, client, user, List.of("openid"), "n-2",
                "https://sso.weldforge.org/t/wellspring");

            @SuppressWarnings("unchecked")
            List<String> roles = (List<String>) parseClaims(out.idToken()).get("roles");
            assertThat(roles).containsExactly("SUPERADMIN");
        }
    }
}
