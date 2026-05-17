package tech.cwvermaak.weldforge.config;

import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import tech.cwvermaak.weldforge.repository.OidcClientRepository;
import tech.cwvermaak.weldforge.repository.TenantRepository;

import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * CORS for the per-tenant OIDC surface.
 *
 * <p>A browser SPA that uses a WeldForge tenant as its OIDC provider fetches
 * the discovery document, JWKS, token and userinfo endpoints cross-origin —
 * those responses need CORS headers or the browser blocks them.
 *
 * <p>The allow-list is <b>data-driven</b>: an {@code Origin} is permitted only
 * when it is registered as a web origin on one of that tenant's OIDC clients
 * ({@code OidcClient.webOrigins}). Nothing is hard-coded — registering the
 * SPA's client is what authorises its origin, and the grant is scoped to that
 * one tenant.
 *
 * <p>These endpoints are credential-free by design: discovery and JWKS are
 * public, the token endpoint authenticates with PKCE, and userinfo uses a
 * bearer token rather than a cookie. So {@code allowCredentials} is
 * {@code false} and only specific registered origins — never a wildcard — are
 * echoed back.
 *
 * <p>Plain {@code http} origins are accepted here as-is; whether an
 * {@code http} origin may be <i>registered</i> at all (loopback-only) is
 * enforced at registration time in {@code OidcClientService}.
 */
@Component
@RequiredArgsConstructor
public class TenantOidcCorsConfigurationSource implements CorsConfigurationSource {

    /**
     * The tenant OIDC endpoints a browser fetches cross-origin. {@code /authorize}
     * is a top-level navigation (CORS does not apply) but is harmless to cover.
     */
    private static final Pattern OIDC_BROWSER_PATH = Pattern.compile(
            "^/t/([a-z0-9][a-z0-9-]{0,62}[a-z0-9])/"
            + "(\\.well-known/openid-configuration|oauth2/(jwks|token|userinfo|authorize))$");

    private final OidcClientRepository oidcClientRepository;
    private final TenantRepository tenantRepository;

    @Override
    public CorsConfiguration getCorsConfiguration(HttpServletRequest request) {
        String path = request.getRequestURI();
        if (path == null) return null;
        Matcher m = OIDC_BROWSER_PATH.matcher(path);
        // Not a tenant OIDC endpoint — signal the caller to fall back to the
        // global CORS configuration.
        if (!m.matches()) return null;

        String slug = m.group(1);
        List<String> origins = tenantRepository.findBySlug(slug)
                .map(t -> oidcClientRepository.findByTenantId(t.getId()).stream()
                        .flatMap(c -> c.getWebOriginList().stream())
                        .distinct()
                        .toList())
                .orElse(List.of());
        // No registered browser client for this tenant — expose no CORS surface.
        if (origins.isEmpty()) return null;

        CorsConfiguration cfg = new CorsConfiguration();
        cfg.setAllowedOrigins(origins);
        cfg.setAllowedMethods(List.of("GET", "POST", "OPTIONS"));
        cfg.setAllowedHeaders(List.of("Authorization", "Content-Type"));
        cfg.setAllowCredentials(false);
        cfg.setMaxAge(3600L);
        return cfg;
    }
}
