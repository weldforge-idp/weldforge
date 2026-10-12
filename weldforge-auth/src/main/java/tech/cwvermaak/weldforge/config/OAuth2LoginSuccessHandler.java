package tech.cwvermaak.weldforge.config;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import tech.cwvermaak.weldforge.config.oauth.SocialRegistrationId;
import tech.cwvermaak.weldforge.config.tenant.PublicHostProperties;
import tech.cwvermaak.weldforge.service.AuthService;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * Turns a completed sign-in at an upstream provider into a WeldForge session.
 *
 * <p>Without this, a social sign-in ended nowhere. {@code oauth2Login} was
 * configured with a user service that provisioned the account and <em>no
 * success handler</em>, under {@link org.springframework.security.config.http.SessionCreationPolicy#STATELESS}.
 * Spring's default handler saves the authentication into an HTTP session that
 * this deployment does not keep, so the person returned from Google
 * authenticated to Spring for the length of one request and anonymous to
 * WeldForge thereafter. The product advertised a sign-in that could not
 * finish.
 *
 * <p>What it does is deliberately the same thing a password login does —
 * {@link AuthService#issueFederatedSession} writes the session cookie and the
 * rotating refresh cookies — so a federated session is not a second kind of
 * session with its own rules. The SPA then picks the session up exactly as it
 * does after any other sign-in: its interceptor refreshes against the cookie.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class OAuth2LoginSuccessHandler implements AuthenticationSuccessHandler {

    private final AuthService authService;
    private final PublicHostProperties publicHost;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication) throws IOException {

        if (!(authentication instanceof OAuth2AuthenticationToken token)) {
            // Not ours to handle; fail closed rather than guessing.
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Unexpected authentication type");
            return;
        }

        // Through the shared parser, which splits on the LAST hyphen. This
        // used to split on the first, so a slug containing one -- most of
        // them -- resolved to the wrong tenant and the lookup below failed
        // after a perfectly good sign-in. See SocialRegistrationId.
        String registrationId = token.getAuthorizedClientRegistrationId();
        var parsed = SocialRegistrationId.parse(registrationId).orElse(null);
        if (parsed == null) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Unrecognised provider registration");
            return;
        }
        String slug = parsed.tenantSlug();

        OAuth2User principal = token.getPrincipal();
        String email = principal.getAttribute("email");
        if (email == null || email.isBlank()) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Provider returned no email address");
            return;
        }

        // The lookup, the session and the audit all happen inside
        // AuthService's transaction rather than here. This method runs in the
        // filter chain, where nothing has opened a persistence context, so an
        // entity loaded at this level is detached and its first lazy
        // association throws -- which is what turned a good Google sign-in
        // into a 500 on 2026-10-11. See issueFederatedSession.
        //
        // CustomOAuth2UserService has already provisioned (or refused) this
        // person, so the row exists by the time we are called. If it does
        // not, something changed underneath us and guessing is worse than
        // failing.
        boolean issued = authService
                .issueFederatedSession(slug, email, parsed.providerKey(), request, response)
                .isPresent();
        if (!issued) {
            log.warn("Social sign-in succeeded but no user row exists: tenant={} email={}", slug, email);
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "No account for this sign-in");
            return;
        }

        response.sendRedirect(destination(request, slug));
    }

    /**
     * Where to send the browser afterwards.
     *
     * <p>An OIDC {@code /authorize} that bounced an unauthenticated user to
     * the login page encodes its own URL in {@code oidcReturnTo}. Honouring it
     * is what makes a social sign-in usable as the first step of an OIDC flow
     * rather than a dead end on the portal home page.
     *
     * <p>The value is only ever used when it decodes to a URL on this
     * deployment's own tenant origin. It arrives from the browser, so treating
     * it as trusted would be an open redirect — the one an OAuth callback is
     * least able to afford.
     */
    private String destination(HttpServletRequest request, String slug) {
        String origin = publicHost.originForTenant(slug);
        String encoded = request.getParameter("oidcReturnTo");
        if (encoded == null || encoded.isBlank()) {
            return origin + "/";
        }
        try {
            String decoded = new String(Base64.getUrlDecoder().decode(encoded), StandardCharsets.UTF_8);
            URI target = URI.create(decoded);
            if (!target.isAbsolute()) return origin + "/";
            String targetOrigin = target.getScheme() + "://" + target.getAuthority();
            // Compare origins, not prefixes: "https://acme.sso.example.evil"
            // starts with the apex host as a string and is not this site.
            if (targetOrigin.equalsIgnoreCase(origin)
                    || targetOrigin.equalsIgnoreCase(publicHost.originForTenant(null))) {
                return decoded;
            }
            log.warn("Refusing oidcReturnTo to a foreign origin: {}", targetOrigin);
        } catch (IllegalArgumentException e) {
            log.warn("Unusable oidcReturnTo on social sign-in for tenant {}", slug);
        }
        return origin + "/";
    }
}
