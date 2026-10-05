package tech.cwvermaak.weldforge.config;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import tech.cwvermaak.weldforge.model.AuthProvider;
import tech.cwvermaak.weldforge.model.Tenant;
import tech.cwvermaak.weldforge.model.User;
import tech.cwvermaak.weldforge.repository.TenantRepository;
import tech.cwvermaak.weldforge.repository.UserRepository;
import tech.cwvermaak.weldforge.service.TenantSeatService;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

/**
 * Provisioning a person who arrived through an upstream provider.
 *
 * <p>Three faults this pins, all of which shipped:
 *
 * <ul>
 *   <li><b>{@code email_verified} was never set.</b> The service read the
 *       address, name and picture and nothing else, so anyone arriving
 *       through Google had {@code email_verified: false} in their token
 *       forever. A relying party that gates on a verified address — which is
 *       the correct thing to do — could never admit them.</li>
 *   <li><b>An existing local account was matched on the address alone.</b>
 *       That is the same hole as the one that let anyone claim another
 *       person's invitation in Project Revelation, on our side of the fence:
 *       trusting an address nobody verified.</li>
 *   <li><b>No tenant could limit who signs in.</b> A tenant federated to a
 *       Workspace accepted any account at that provider; the sign-in URL was
 *       the only obstacle, and a URL is not an access control.</li>
 * </ul>
 */
@DisplayName("Social sign-in provisioning")
class CustomOAuth2UserServiceTest {

    private static final String REGISTRATION = "acme-google";

    private UserRepository users;
    private TenantRepository tenants;
    private CustomOAuth2UserService service;
    private Tenant tenant;

    @BeforeEach
    void setUp() {
        users = mock(UserRepository.class);
        tenants = mock(TenantRepository.class);
        TenantSeatService seats = mock(TenantSeatService.class);
        service = new CustomOAuth2UserService(users, tenants, seats);

        tenant = Tenant.builder().id(1L).slug("acme").name("Acme").build();
        when(tenants.findBySlug("acme")).thenReturn(Optional.of(tenant));
        when(users.save(any())).thenAnswer(inv -> inv.getArgument(0));
        when(users.findByTenantIdAndEmailIgnoreCase(anyLong(), anyString()))
                .thenReturn(Optional.empty());
    }

    /** A principal shaped like the provider's userinfo response. */
    private OAuth2User principal(Map<String, Object> attrs) {
        Map<String, Object> all = new HashMap<>(attrs);
        all.putIfAbsent("sub", "provider-subject-1");
        return new DefaultOAuth2User(List.of(new SimpleGrantedAuthority("ROLE_USER")), all, "sub");
    }

    private User captureSaved() {
        var captor = org.mockito.ArgumentCaptor.forClass(User.class);
        verify(users).save(captor.capture());
        return captor.getValue();
    }

    @Nested
    @DisplayName("email_verified")
    class EmailVerified {

        @Test
        @DisplayName("a verified provider address marks the account verified")
        void verifiedIsCarried() {
            service.provision(REGISTRATION, principal(Map.of(
                    "email", "alice@acme.test", "name", "Alice", "email_verified", true)));

            assertThat(captureSaved().isEmailVerified())
                    .as("without this, no relying party gating on a verified address can admit them")
                    .isTrue();
        }

        @Test
        @DisplayName("the string \"true\" counts — providers differ in shape")
        void stringTrue() {
            service.provision(REGISTRATION, principal(Map.of(
                    "email", "alice@acme.test", "email_verified", "true")));
            assertThat(captureSaved().isEmailVerified()).isTrue();
        }

        @Test
        @DisplayName("GitHub's verified_email spelling also counts")
        void altSpelling() {
            service.provision(REGISTRATION, principal(Map.of(
                    "email", "alice@acme.test", "verified_email", true)));
            assertThat(captureSaved().isEmailVerified()).isTrue();
        }

        @Test
        @DisplayName("an ABSENT claim is not verified — the dangerous default")
        void absentIsNotVerified() {
            service.provision(REGISTRATION, principal(Map.of(
                    "email", "alice@acme.test", "name", "Alice")));

            assertThat(captureSaved().isEmailVerified())
                    .as("reading a missing claim as true turns an unverified address into an identity")
                    .isFalse();
        }

        @Test
        @DisplayName("an explicit false is not verified")
        void explicitFalse() {
            service.provision(REGISTRATION, principal(Map.of(
                    "email", "alice@acme.test", "email_verified", false)));
            assertThat(captureSaved().isEmailVerified()).isFalse();
        }

        @Test
        @DisplayName("a person already verified here is never demoted")
        void neverDemotes() {
            User existing = User.builder().id(7L).tenant(tenant).email("alice@acme.test")
                    .emailVerified(true).build();
            when(users.findByTenantIdAndEmailIgnoreCase(1L, "alice@acme.test"))
                    .thenReturn(Optional.of(existing));

            // Provider asserts nothing; they verified with us previously.
            service.provision(REGISTRATION, principal(Map.of(
                    "email", "alice@acme.test", "email_verified", true)));

            assertThat(existing.isEmailVerified()).isTrue();
        }
    }

    @Nested
    @DisplayName("linking to an account that already exists")
    class Linking {

        @Test
        @DisplayName("refused when the provider did not verify the address")
        void refusesUnverifiedLink() {
            User existing = User.builder().id(7L).tenant(tenant).email("alice@acme.test")
                    .provider(AuthProvider.LOCAL).build();
            when(users.findByTenantIdAndEmailIgnoreCase(1L, "alice@acme.test"))
                    .thenReturn(Optional.of(existing));

            assertThatThrownBy(() -> service.provision(REGISTRATION, principal(Map.of(
                    "email", "alice@acme.test"))))
                    .isInstanceOf(OAuth2AuthenticationException.class);

            verify(users, never()).save(any());
        }

        @Test
        @DisplayName("allowed when the provider DID verify it")
        void allowsVerifiedLink() {
            User existing = User.builder().id(7L).tenant(tenant).email("alice@acme.test")
                    .provider(AuthProvider.LOCAL).build();
            when(users.findByTenantIdAndEmailIgnoreCase(1L, "alice@acme.test"))
                    .thenReturn(Optional.of(existing));

            assertThatCode(() -> service.provision(REGISTRATION, principal(Map.of(
                    "email", "alice@acme.test", "email_verified", true))))
                    .doesNotThrowAnyException();
        }
    }

    @Nested
    @DisplayName("the tenant's domain allow-list")
    class DomainGate {

        @Test
        @DisplayName("an outside domain is refused")
        void refusesOutsider() {
            tenant.setAllowedEmailDomains("acme.test");

            assertThatThrownBy(() -> service.provision(REGISTRATION, principal(Map.of(
                    "email", "stranger@gmail.com", "email_verified", true))))
                    .isInstanceOf(OAuth2AuthenticationException.class);

            verify(users, never()).save(any());
        }

        @Test
        @DisplayName("an allowed domain gets in")
        void admitsMember() {
            tenant.setAllowedEmailDomains("acme.test");

            assertThatCode(() -> service.provision(REGISTRATION, principal(Map.of(
                    "email", "alice@acme.test", "email_verified", true))))
                    .doesNotThrowAnyException();
        }

        @Test
        @DisplayName("Google's hd must also be allowed, even when the address is")
        void hostedDomainChecked() {
            tenant.setAllowedEmailDomains("acme.test");

            assertThatThrownBy(() -> service.provision(REGISTRATION, principal(Map.of(
                    "email", "alice@acme.test", "email_verified", true,
                    "hd", "someone-else.test"))))
                    .isInstanceOf(OAuth2AuthenticationException.class);
        }

        @Test
        @DisplayName("no list set restricts nothing — every tenant today")
        void unrestrictedByDefault() {
            assertThatCode(() -> service.provision(REGISTRATION, principal(Map.of(
                    "email", "anyone@anywhere.test", "email_verified", true))))
                    .doesNotThrowAnyException();
        }
    }
}
