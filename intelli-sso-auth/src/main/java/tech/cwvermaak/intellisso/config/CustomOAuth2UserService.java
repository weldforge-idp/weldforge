package tech.cwvermaak.intellisso.config;

import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import tech.cwvermaak.intellisso.model.AuthProvider;
import tech.cwvermaak.intellisso.model.User;
import tech.cwvermaak.intellisso.repository.UserRepository;

@Service
@RequiredArgsConstructor
public class CustomOAuth2UserService extends DefaultOAuth2UserService {

    private final UserRepository userRepository;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2User oAuth2User = super.loadUser(userRequest);

        String registrationId = userRequest.getClientRegistration().getRegistrationId().toUpperCase();
        String email = oAuth2User.getAttribute("email");
        if (email == null) {
            throw new OAuth2AuthenticationException("Email not found from OAuth2 provider");
        }

        String name = oAuth2User.getAttribute("name");
        String imageUrl = oAuth2User.getAttribute("picture") != null ?
                oAuth2User.getAttribute("picture") :
                oAuth2User.getAttribute("avatar_url");

        AuthProvider provider = AuthProvider.valueOf(registrationId);

        User user = userRepository.findByEmail(email)
                .orElseGet(() -> User.builder()
                        .email(email)
                        .provider(provider)
                        .providerId(oAuth2User.getName())
                        .build());

        // Update fields if changed
        user.setName(name);
        user.setImageUrl(imageUrl);

        userRepository.save(user);

        return oAuth2User;
    }
}