package tech.cwvermaak.weldforge.config.tenant;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Resolves the current tenant from the incoming request and stashes the
 * slug in {@link TenantContext}. Resolution order:
 *
 *   1. {@code X-Tenant-Slug} header — machine clients and the
 *      super-admin tenant picker.
 *   2. {@code /t/{slug}/...} path prefix — OIDC/SAML deep-link endpoints
 *      that stay on the apex host.
 *   3. Host header subdomain — the per-tenant auth subdomain pattern
 *      {@code {slug}.{publicHost.baseDomain}}. This is what end-user
 *      auth pages (login, forgot-password, reset-password, register,
 *      verify-email) use so password managers see each tenant as a
 *      distinct site. See {@code docs/auth-url-spec.md}.
 *   4. Fallback to {@code default} so single-tenant deployments and
 *      tests without any host/path context still resolve.
 *
 * Runs before the JWT filter so downstream auth/resolution has the
 * tenant in scope.
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE + 10)
@RequiredArgsConstructor
public class TenantResolverFilter extends OncePerRequestFilter {

    public static final String HEADER = "X-Tenant-Slug";
    public static final String DEFAULT_TENANT = "default";

    /**
     * {@code /t/{slug}/...} path-prefix matcher. Exposed package-public so
     * downstream filters ({@code JwtAuthenticationFilter}) can compute the
     * same "implicit tenant" (host or path) they need to enforce against
     * the JWT's {@code tenant_id} claim — see {@code docs/auth-url-spec.md}
     * §"Cross-tenant cookie safety".
     */
    public static final Pattern PATH_PREFIX =
            Pattern.compile("^/t/([a-z0-9][a-z0-9-]{0,62}[a-z0-9])(/|$)");

    private final PublicHostProperties publicHost;

    /**
     * Recompute the request's implicit tenant — the slug derived from the
     * Host header subdomain or the {@code /t/{slug}/...} path prefix, but
     * NOT from the {@code X-Tenant-Slug} header. The header is the explicit
     * cross-tenant channel reserved for super-admin and machine clients;
     * callers that want to enforce per-request tenant binding should compare
     * the JWT's {@code tenant_id} against this implicit value, not against
     * the resolver's final pick.
     *
     * <p>Returns {@code null} when neither host nor path identifies a
     * tenant (the apex domain, single-host dev setups, non-tenant paths).</p>
     */
    public String implicitTenantSlug(HttpServletRequest request) {
        String path = request.getRequestURI();
        if (path != null) {
            Matcher m = PATH_PREFIX.matcher(path);
            if (m.find()) return m.group(1);
        }
        return publicHost.slugFromHost(request.getServerName());
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {
        try {
            String slug = resolve(request);
            TenantContext.set(slug);
            chain.doFilter(request, response);
        } finally {
            TenantContext.clear();
        }
    }

    private String resolve(HttpServletRequest request) {
        String header = request.getHeader(HEADER);
        if (header != null && !header.isBlank()) return header.trim().toLowerCase();

        // server.forward-headers-strategy=native makes getServerName() reflect
        // X-Forwarded-Host, so this works behind the GCP load balancer as well
        // as a direct request to the backend in dev.
        String implicit = implicitTenantSlug(request);
        if (implicit != null) return implicit;

        return DEFAULT_TENANT;
    }
}
