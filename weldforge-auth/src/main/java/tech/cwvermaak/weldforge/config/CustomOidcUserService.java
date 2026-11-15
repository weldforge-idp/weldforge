package tech.cwvermaak.weldforge.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Service;

/**
 * The OpenID Connect half of social sign-in: Google, Microsoft, Apple and
 * LinkedIn all ask for the {@code openid} scope.
 *
 * <p>Spring Security sends any sign-in whose scope includes {@code openid}
 * down a different path from plain OAuth2: {@code OidcAuthorizationCodeAuthenticationProvider}
 * and an {@code OidcUserService}, not the {@code userService} configured on
 * {@code oauth2Login().userInfoEndpoint()}. Only that one was configured, so
 * {@link CustomOAuth2UserService#provision} -- every check on who may enter a
 * tenant -- ran for GitHub, Facebook and Twitter and for none of the providers
 * that speak OIDC. Those sign-ins skipped the email-verified check before
 * linking to an existing account, the tenant's domain allow-list, the
 * provider's required hosted domain and the seat cap (security review
 * 2026-11-15). For a provider that does not assert email_verified, such as
 * Microsoft's multi-tenant endpoint, that let anyone who controls a directory
 * set an account's email to someone else's address and be signed in as them.
 *
 * <p>The ID token is still validated by Spring first (signature, issuer where
 * configured, audience, nonce, expiry); this only adds the same provisioning
 * decision the OAuth2 path makes, against the merged ID-token and userinfo
 * claims.
 */
@Service
public class CustomOidcUserService implements OAuth2UserService<OidcUserRequest, OidcUser> {

    private final CustomOAuth2UserService provisioning;
    private final OAuth2UserService<OidcUserRequest, OidcUser> delegate;

    @Autowired
    public CustomOidcUserService(CustomOAuth2UserService provisioning) {
        this(provisioning, new OidcUserService());
    }

    /** For tests: lets the provider round-trip be replaced. */
    CustomOidcUserService(CustomOAuth2UserService provisioning,
                          OAuth2UserService<OidcUserRequest, OidcUser> delegate) {
        this.provisioning = provisioning;
        this.delegate = delegate;
    }

    @Override
    public OidcUser loadUser(OidcUserRequest userRequest) throws OAuth2AuthenticationException {
        OidcUser oidcUser = delegate.loadUser(userRequest);
        // Throws OAuth2AuthenticationException to refuse; returns the same
        // principal on success, so the success handler is unchanged.
        provisioning.provision(userRequest.getClientRegistration().getRegistrationId(), oidcUser);
        return oidcUser;
    }
}
