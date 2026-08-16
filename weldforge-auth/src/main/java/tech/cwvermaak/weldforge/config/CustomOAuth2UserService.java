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

        String registrationId = userRequest.getClientRegistration().getRegistrationId();
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

        User user = userRepository.findByTenantIdAndEmailIgnoreCase(tenant.getId(), email)
                .orElseGet(() -> User.builder()
                        .tenant(tenant)
                        .email(email)
                        .username(email)
                        .provider(provider)
                        .providerId(oAuth2User.getName())
                        .build());

        // Just-in-time provisioning consumes a seat. Only a brand-new user
        // (no id yet) does — an existing user signing in again does not.
        if (user.getId() == null) {
            assertSeatAvailable(tenant);
        }

        user.setName(name);
        user.setImageUrl(imageUrl);
        userRepository.save(user);

        return oAuth2User;
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
