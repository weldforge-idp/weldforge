package tech.cwvermaak.weldforge.service.oidc;

import io.jsonwebtoken.Jwts;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;
import tech.cwvermaak.weldforge.model.OidcClient;
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
 * Contract test for the {@code amr} claim (RFC 8176). A relying party may
 * release a secret only to a session established with a phishing-resistant
 * factor, so what matters here is that the claim reports the factors the login
 * actually exercised — and that nothing else can put a value there.
 */
@DisplayName("OidcTokenService — amr claim emission")
class OidcTokenServiceAmrClaimTest {

    private static final String ISSUER = "https://sso.weldforge.org/t/cwvermaak-tech";

    private OidcTokenService service;
    private PublicKey publicKey;
    private Tenant tenant;
    private OidcClient client;
    private User user;

    @BeforeEach
    void setUp() throws Exception {
        KeyPair kp = KeyPairGenerator.getInstance("RSA").genKeyPair();
        RSAPrivateKey privateKey = (RSAPrivateKey) kp.getPrivate();
        publicKey = kp.getPublic();

        TenantSigningKeyService signingKeyService = mock(TenantSigningKeyService.class);
        TenantSigningKey signingKey = mock(TenantSigningKey.class);
        when(signingKey.getKid()).thenReturn("test-kid");
        when(signingKeyService.getOrCreateActive(any())).thenReturn(signingKey);
        when(signingKeyService.loadPrivateKey(any())).thenReturn(privateKey);

        service = new OidcTokenService(signingKeyService, new SimpleMeterRegistry());
        ReflectionTestUtils.setField(service, "accessTokenSeconds", 3600L);
        ReflectionTestUtils.setField(service, "idTokenSeconds", 3600L);

        tenant = Tenant.builder()
                .id(5L).slug("cwvermaak-tech").name("CWVermaak Tech")
                .accessTtlMs(3_600_000L)
                .build();
        client = OidcClient.builder()
                .id(22L).tenant(tenant).clientId("keycrypt-desktop")
                .build();
        user = User.builder()
                .id(7L).tenant(tenant)
                .username("operator").email("operator@cwvermaak.tech")
                .build();
    }

    private Map<String, Object> parseClaims(String token) {
        return Jwts.parser().verifyWith(publicKey).build().parseSignedClaims(token).getPayload();
    }

    @SuppressWarnings("unchecked")
    private static List<String> amrOf(Map<String, Object> claims) {
        return (List<String>) claims.get("amr");
    }

    @Nested
    @DisplayName("Given a login that used a WebAuthn second factor")
    class PhishingResistantLogin {

        @Test
        @DisplayName("Then the access token reports pwd, hwk and mfa")
        void accessTokenCarriesAmr() {
            OidcTokenService.IssuedTokens out = service.issueForCodeExchange(
                    tenant, client, user, List.of("openid"), "n-1", ISSUER,
                    List.of("pwd", "hwk", "mfa"));

            assertThat(amrOf(parseClaims(out.accessToken())))
                    .containsExactly("pwd", "hwk", "mfa");
        }

        @Test
        @DisplayName("And the ID token reports the same methods — an RP validating "
                   + "either artefact reaches the same decision")
        void idTokenCarriesAmr() {
            OidcTokenService.IssuedTokens out = service.issueForCodeExchange(
                    tenant, client, user, List.of("openid"), "n-1", ISSUER,
                    List.of("pwd", "hwk", "mfa"));

            assertThat(amrOf(parseClaims(out.idToken())))
                    .containsExactly("pwd", "hwk", "mfa");
        }
    }

    @Nested
    @DisplayName("Given a login that used only a password")
    class PasswordOnlyLogin {

        @Test
        @DisplayName("Then the token reports pwd alone, so a relying party requiring "
                   + "a phishing-resistant factor rejects it")
        void weakLoginIsReportedHonestly() {
            OidcTokenService.IssuedTokens out = service.issueForCodeExchange(
                    tenant, client, user, List.of("openid"), null, ISSUER, List.of("pwd"));

            assertThat(amrOf(parseClaims(out.accessToken())))
                    .containsExactly("pwd")
                    .doesNotContain("hwk", "swk", "mfa");
        }
    }

    @Nested
    @DisplayName("Given nothing is known about how the session was established")
    class UnknownAuthentication {

        @Test
        @DisplayName("Then the claim is absent rather than an empty array — "
                   + "'nothing asserted', not 'authenticated by no method'")
        void absentNotEmpty() {
            OidcTokenService.IssuedTokens nulled = service.issueForCodeExchange(
                    tenant, client, user, List.of("openid"), null, ISSUER, null);
            OidcTokenService.IssuedTokens empty = service.issueForCodeExchange(
                    tenant, client, user, List.of("openid"), null, ISSUER, List.of());

            assertThat(parseClaims(nulled.accessToken())).doesNotContainKey("amr");
            assertThat(parseClaims(nulled.idToken())).doesNotContainKey("amr");
            assertThat(parseClaims(empty.accessToken())).doesNotContainKey("amr");
        }

        @Test
        @DisplayName("And the overload without an amr argument omits it too, so an "
                   + "un-migrated call site cannot invent a factor")
        void legacyOverloadOmitsIt() {
            OidcTokenService.IssuedTokens out = service.issueForCodeExchange(
                    tenant, client, user, List.of("openid"), null, ISSUER);

            assertThat(parseClaims(out.accessToken())).doesNotContainKey("amr");
        }
    }

    @Nested
    @DisplayName("Given a client-credentials grant — there is no end-user")
    class ClientCredentials {

        @Test
        @DisplayName("Then no amr is emitted: the claim describes how a person "
                   + "authenticated, and no person is involved")
        void noAmrWithoutAUser() {
            OidcTokenService.IssuedTokens out =
                    service.issueForClientCredentials(tenant, client, List.of("api"), ISSUER);

            assertThat(parseClaims(out.accessToken())).doesNotContainKey("amr");
        }
    }

    @Nested
    @DisplayName("Given a tenant configured with a custom amr claim")
    class ForgedByConfiguration {

        @Test
        @DisplayName("Then it is dropped — tenant config must not be able to assert "
                   + "a factor the user never presented")
        void tenantCustomClaimCannotForgeAmr() {
            tenant.setCustomClaims(Map.of("amr", List.of("hwk"), "department", "platform"));

            OidcTokenService.IssuedTokens out = service.issueForCodeExchange(
                    tenant, client, user, List.of("openid"), null, ISSUER, List.of("pwd"));

            Map<String, Object> claims = parseClaims(out.accessToken());
            assertThat(amrOf(claims)).containsExactly("pwd");
            // The rest of the tenant's custom claims still come through.
            assertThat(claims.get("department")).isEqualTo("platform");
        }

        @Test
        @DisplayName("And it cannot smuggle one in when the login reported none")
        void cannotSupplyAmrWhereThereIsNone() {
            tenant.setCustomClaims(Map.of("amr", List.of("hwk")));

            OidcTokenService.IssuedTokens out = service.issueForCodeExchange(
                    tenant, client, user, List.of("openid"), null, ISSUER, null);

            assertThat(parseClaims(out.accessToken())).doesNotContainKey("amr");
        }
    }
}
