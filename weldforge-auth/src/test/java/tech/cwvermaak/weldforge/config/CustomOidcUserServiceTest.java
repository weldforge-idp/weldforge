package tech.cwvermaak.weldforge.config;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import tech.cwvermaak.weldforge.model.AuthProvider;
import tech.cwvermaak.weldforge.model.SocialProviderType;
import tech.cwvermaak.weldforge.model.Tenant;
import tech.cwvermaak.weldforge.model.TenantSocialProvider;
import tech.cwvermaak.weldforge.model.User;
import tech.cwvermaak.weldforge.repository.TenantRepository;
import tech.cwvermaak.weldforge.repository.TenantSocialProviderRepository;
import tech.cwvermaak.weldforge.repository.UserRepository;
import tech.cwvermaak.weldforge.service.TenantSeatService;

import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * The OIDC providers (Google, Microsoft, Apple, LinkedIn) reach the same
 * provisioning decision as the OAuth2 ones. Before 2026-11-15 Spring routed
 * them through its default OidcUserService and none of these checks ran.
 */
@DisplayName("OIDC social sign-in goes through provisioning")
class CustomOidcUserServiceTest {

    private UserRepository users;
    private TenantSocialProviderRepository providers;
    private CustomOidcUserService service;
    private Tenant tenant;
    private Map<String, Object> claims;

    @BeforeEach
    void setUp() {
        users = mock(UserRepository.class);
        TenantRepository tenants = mock(TenantRepository.class);
        providers = mock(TenantSocialProviderRepository.class);
        when(providers.findByTenant_SlugAndProviderAndEnabledTrue(anyString(), any())).thenReturn(Optional.empty());
        CustomOAuth2UserService provisioning =
                new CustomOAuth2UserService(users, tenants, mock(TenantSeatService.class), providers);

        tenant = Tenant.builder().id(1L).slug("acme").name("Acme").build();
        when(tenants.findBySlug("acme")).thenReturn(Optional.of(tenant));
        when(users.save(any())).thenAnswer(inv -> inv.getArgument(0));
        when(users.findByTenantIdAndEmailIgnoreCase(anyLong(), anyString())).thenReturn(Optional.empty());

        claims = new HashMap<>(Map.of("sub", "upstream-123", "email", "victim@corp.example",
                "name", "Victim", "iss", "https://login.microsoftonline.com/attacker-tenant/v2.0"));
        // The provider round-trip is replaced: what matters is what happens to
        // the principal Spring hands back.
        service = new CustomOidcUserService(provisioning, req -> oidcUser(claims));
    }

    private static OidcUser oidcUser(Map<String, Object> claims) {
        OidcIdToken idToken = new OidcIdToken("id-token", Instant.now(), Instant.now().plusSeconds(300), claims);
        return new DefaultOidcUser(List.of(new SimpleGrantedAuthority("OIDC_USER")), idToken);
    }

    private static OidcUserRequest request(String registrationId) {
        ClientRegistration reg = ClientRegistration.withRegistrationId(registrationId)
                .clientId("c").clientSecret("s")
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
                .scope("openid", "profile", "email")
                .authorizationUri("https://idp.example/authorize")
                .tokenUri("https://idp.example/token")
                .jwkSetUri("https://idp.example/keys")
                .build();
        OAuth2AccessToken at = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, "at",
                Instant.now(), Instant.now().plusSeconds(300));
        OidcIdToken idToken = new OidcIdToken("id-token", Instant.now(), Instant.now().plusSeconds(300),
                Map.of("sub", "upstream-123"));
        return new OidcUserRequest(reg, at, idToken);
    }

    private User existingAccount() {
        return User.builder().id(42L).tenant(tenant).email("victim@corp.example")
                .provider(AuthProvider.LOCAL).build();
    }

    @Test
    @DisplayName("an unverified address from a Microsoft directory cannot take over an existing account (nOAuth)")
    void unverifiedEmailCannotLinkToExistingAccount() {
        when(users.findByTenantIdAndEmailIgnoreCase(1L, "victim@corp.example"))
                .thenReturn(Optional.of(existingAccount()));

        assertThatThrownBy(() -> service.loadUser(request("acme-microsoft")))
                .isInstanceOf(OAuth2AuthenticationException.class)
                .satisfies(e -> assertThat(((OAuth2AuthenticationException) e).getError().getErrorCode())
                        .isEqualTo("email_not_verified"));
        verify(users, never()).save(any());
    }

    @Test
    @DisplayName("a verified address links to the existing account")
    void verifiedEmailLinks() {
        User existing = existingAccount();
        when(users.findByTenantIdAndEmailIgnoreCase(1L, "victim@corp.example")).thenReturn(Optional.of(existing));
        claims.put("email_verified", true);

        OidcUser result = service.loadUser(request("acme-google"));

        assertThat(result.getEmail()).isEqualTo("victim@corp.example");
        assertThat(existing.isEmailVerified()).isTrue();
        verify(users).save(existing);
    }

    @Test
    @DisplayName("the tenant's email-domain allow-list applies to OIDC providers")
    void domainAllowListApplies() {
        tenant.setAllowedEmailDomains("acme.example");
        claims.put("email_verified", true);

        assertThatThrownBy(() -> service.loadUser(request("acme-google")))
                .isInstanceOf(OAuth2AuthenticationException.class)
                .satisfies(e -> assertThat(((OAuth2AuthenticationException) e).getError().getErrorCode())
                        .isEqualTo("domain_not_allowed"));
    }

    @Test
    @DisplayName("a provider's required hosted domain refuses a consumer Google account")
    void requiredHostedDomainApplies() {
        TenantSocialProvider google = TenantSocialProvider.builder()
                .tenant(tenant).provider(SocialProviderType.GOOGLE).requiredHd("acme.example").enabled(true).build();
        when(providers.findByTenant_SlugAndProviderAndEnabledTrue("acme", SocialProviderType.GOOGLE))
                .thenReturn(Optional.of(google));
        claims.put("email", "someone@acme.example");
        claims.put("email_verified", true); // a consumer account on the domain's address: no hd

        assertThatThrownBy(() -> service.loadUser(request("acme-google")))
                .isInstanceOf(OAuth2AuthenticationException.class)
                .satisfies(e -> assertThat(((OAuth2AuthenticationException) e).getError().getErrorCode())
                        .isEqualTo("hosted_domain_required"));
    }

    @Test
    @DisplayName("a first-time OIDC user is provisioned (they used to get 401 'No account for this sign-in')")
    void firstTimeUserIsProvisioned() {
        claims.put("email_verified", true);

        service.loadUser(request("acme-google"));

        verify(users).save(any(User.class));
    }
}
