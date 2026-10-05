package tech.cwvermaak.weldforge.config.oauth;

import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;

/**
 * Asking for a provider a tenant has not configured is a 404, not a 500.
 *
 * <p>{@code /oauth2/authorization/**} is public and unauthenticated, and the
 * registration id is part of the URL — so anyone, including a crawler, can
 * ask for {@code {slug}-{provider}} combinations that do not exist. Spring's
 * default resolver throws {@link InvalidClientRegistrationIdException} from
 * inside the filter chain, where no {@code @ControllerAdvice} can reach it,
 * and the container renders a generic 500.
 *
 * <p>That matters for two reasons beyond tidiness. A 500 on a public path is
 * indistinguishable from the service being broken, so it pollutes the
 * monitoring that is supposed to tell us when it actually is. And it tells an
 * administrator who has mistyped a provider name nothing about what is wrong.
 *
 * <p>Returning null instead lets the filter chain continue; nothing else
 * matches that path, so the request ends as a 404 — which is the honest
 * answer to "that provider is not configured here".
 *
 * <p>Only reachable because the path now routes to this service at all: until
 * 2026-10-05 the ingress sent it to the SPA, which answered 200 with an HTML
 * page, and no social sign-in could start.
 */
@Slf4j
public class UnknownRegistrationTolerantResolver implements OAuth2AuthorizationRequestResolver {

    private final DefaultOAuth2AuthorizationRequestResolver delegate;
    private final ClientRegistrationRepository repository;
    private final String baseUri;

    public UnknownRegistrationTolerantResolver(ClientRegistrationRepository repository,
                                               String authorizationRequestBaseUri) {
        this.repository = repository;
        this.baseUri = authorizationRequestBaseUri;
        this.delegate = new DefaultOAuth2AuthorizationRequestResolver(
                repository, authorizationRequestBaseUri);
    }

    @Override
    public OAuth2AuthorizationRequest resolve(HttpServletRequest request) {
        String id = registrationIdFrom(request);
        if (id == null) return null;
        return resolve(request, id);
    }

    @Override
    public OAuth2AuthorizationRequest resolve(HttpServletRequest request, String clientRegistrationId) {
        if (clientRegistrationId == null || repository.findByRegistrationId(clientRegistrationId) == null) {
            return unconfigured(request);
        }
        return delegate.resolve(request, clientRegistrationId);
    }

    /** The trailing path segment of {@code {baseUri}/{registrationId}}. */
    private String registrationIdFrom(HttpServletRequest request) {
        String uri = request.getRequestURI();
        String prefix = baseUri + "/";
        if (uri == null || !uri.startsWith(prefix)) return null;
        String id = uri.substring(prefix.length());
        // One segment only: anything further down the path is not a
        // registration id and must not be treated as one.
        return id.isBlank() || id.contains("/") ? null : id;
    }

    private OAuth2AuthorizationRequest unconfigured(HttpServletRequest request) {
        // Logged at INFO, not WARN: an unconfigured provider is a normal
        // answer to a public URL, not an incident. Logging it as a problem
        // would make the next real problem harder to see.
        log.info("No social provider configured for {}", request.getRequestURI());
        return null;
    }
}
