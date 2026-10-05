package tech.cwvermaak.weldforge.config;

import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import tech.cwvermaak.weldforge.model.AuthProvider;
import tech.cwvermaak.weldforge.model.Tenant;
import tech.cwvermaak.weldforge.model.User;
import tech.cwvermaak.weldforge.repository.TenantRepository;
import tech.cwvermaak.weldforge.repository.UserRepository;
import tech.cwvermaak.weldforge.service.EmailDomainPolicy;

import java.util.List;

/**
 * Federates the OAuth2 user returned by a per-tenant social provider into a
 * {@link User} row scoped to that tenant. The tenant is pulled off the
 * {@code registrationId}, which this app encodes as
 * {@code {tenantSlug}-{provider}} (see DatabaseClientRegistrationRepository).
 */
@Service
@RequiredArgsConstructor
public class CustomOAuth2UserService extends DefaultOAuth2UserService {

    private final UserRepository userRepository;
    private final TenantRepository tenantRepository;
    private final tech.cwvermaak.weldforge.service.TenantSeatService seatService;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2User oAuth2User = super.loadUser(userRequest);
        return provision(userRequest.getClientRegistration().getRegistrationId(), oAuth2User);
    }

    /**
     * Decide whether this sign-in is allowed, and provision the account.
     *
     * <p>Separated from {@link #loadUser} so the decision can be tested
     * without standing up a provider: loadUser's only other job is an HTTP
     * call to the userinfo endpoint. Everything that determines WHO gets into
     * a tenant lives here.
     */
    OAuth2User provision(String registrationId, OAuth2User oAuth2User) {
        int sep = registrationId.lastIndexOf('-');
        if (sep <= 0) {
            throw new OAuth2AuthenticationException(new OAuth2Error("invalid_registration"),
                    "Registration id must be of the form {tenantSlug}-{provider}");
        }
        String tenantSlug = registrationId.substring(0, sep);
        String providerName = registrationId.substring(sep + 1).toUpperCase();

        Tenant tenant = tenantRepository.findBySlug(tenantSlug)
                .orElseThrow(() -> new OAuth2AuthenticationException(new OAuth2Error("unknown_tenant"),
                        "No tenant found for slug " + tenantSlug));

        String email = oAuth2User.getAttribute("email");
        if (email == null) {
            throw new OAuth2AuthenticationException(new OAuth2Error("email_missing"),
                    "Email not found from OAuth2 provider");
        }

        String name = oAuth2User.getAttribute("name");
        Object pic = oAuth2User.getAttribute("picture");
        String imageUrl = pic != null ? pic.toString() : oAuth2User.getAttribute("avatar_url");

        AuthProvider provider = AuthProvider.valueOf(providerName);

        // Did the provider actually say the address is theirs?
        //
        // Google sends email_verified as a boolean; some providers send the
        // string "true"; some send nothing. Absent is NOT verified. Reading a
        // missing claim as true is how an unverified address becomes a
        // verified identity.
        boolean providerVerifiedEmail = truthy(oAuth2User.getAttribute("email_verified"))
                || truthy(oAuth2User.getAttribute("verified_email")); // GitHub/older Google shape

        // WF2: the tenant's domain allow-list. A tenant federated to a
        // Workspace accepts any account at that provider unless something
        // says otherwise, and the sign-in URL is not an access control.
        // Google's hd names the organisation, which is the thing being
        // admitted -- an address can sit in one domain while the account
        // belongs to another.
        String hostedDomain = asString(oAuth2User.getAttribute("hd"));
        List<String> allowedDomains = EmailDomainPolicy.parse(tenant.getAllowedEmailDomains());
        if (!EmailDomainPolicy.permits(allowedDomains, email, hostedDomain)) {
            throw new OAuth2AuthenticationException(new OAuth2Error("domain_not_allowed"),
                    "This tenant does not accept sign-ins from that email domain");
        }

        User existing = userRepository.findByTenantIdAndEmailIgnoreCase(tenant.getId(), email)
                .orElse(null);

        // Linking an external identity to an account that already exists is
        // an account takeover unless the provider vouches for the address.
        // This is the same hole, on our side, as the one that let anyone
        // claim another person's invitation in Project Revelation: trusting
        // an address nobody verified.
        //
        // Refuse rather than silently create a second account: a duplicate
        // would be indistinguishable to the user from a successful sign-in
        // and would quietly split their history in two.
        if (existing != null && !providerVerifiedEmail) {
            throw new OAuth2AuthenticationException(new OAuth2Error("email_not_verified"),
                    "The provider did not verify this address, and an account already "
                    + "exists for it in this tenant");
        }

        User user = existing != null ? existing
                : User.builder()
                        .tenant(tenant)
                        .email(email)
                        .username(email)
                        .provider(provider)
                        .providerId(oAuth2User.getName())
                        .build();

        // Just-in-time provisioning consumes a seat. Only a brand-new user
        // (no id yet) does — an existing user signing in again does not.
        if (user.getId() == null) {
            assertSeatAvailable(tenant);
        }

        user.setName(name);
        user.setImageUrl(imageUrl);
        // Carry the provider's assertion. Only ever upwards: a person who
        // verified with us and then signs in through a provider that does not
        // verify must not be demoted to unverified, and a provider saying yes
        // is a real verification of the same address.
        if (providerVerifiedEmail) {
            user.setEmailVerified(true);
        }
        userRepository.save(user);

        return oAuth2User;
    }

    /** A provider flag that may arrive as a boolean or as a string. */
    private static boolean truthy(Object value) {
        if (value instanceof Boolean b) return b;
        return value != null && "true".equalsIgnoreCase(value.toString().trim());
    }

    private static String asString(Object value) {
        return value == null ? null : value.toString();
    }

    /**
     * Translate a seat-cap refusal into an OAuth2 error. Without this the
     * runtime exception surfaces to a first-time social sign-in as an opaque
     * 500; as an {@code OAuth2AuthenticationException} it flows through the
     * normal failure handler and the user sees why they were turned away.
     */
    private void assertSeatAvailable(Tenant tenant) {
        try {
            seatService.assertCapacity(tenant);
        } catch (tech.cwvermaak.weldforge.service.SeatLimitExceededException e) {
            throw new OAuth2AuthenticationException(new OAuth2Error("seat_limit_exceeded"), e.getMessage(), e);
        }
    }
}
