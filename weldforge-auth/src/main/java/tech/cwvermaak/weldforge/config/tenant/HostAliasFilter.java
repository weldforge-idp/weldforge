package tech.cwvermaak.weldforge.config.tenant;

import jakarta.servlet.FilterChain;
import jakarta.servlet.RequestDispatcher;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import tech.cwvermaak.weldforge.model.TenantHost;
import tech.cwvermaak.weldforge.repository.TenantHostRepository;

import java.io.IOException;
import java.util.Set;

/**
 * Serves OIDC / SAML public endpoints under a customer-owned hostname.
 * When the Host header matches a row in {@code tenant_hosts}, requests
 * to /.well-known/openid-configuration, /oauth2/**, /saml2/idp/**, /pki/**
 * are internally forwarded to /t/{slug}/... so the existing path-based
 * controllers serve them unchanged.
 *
 * The original host stays in the request line (forward preserves
 * scheme + host + port), so request.getServerName() after the forward
 * still returns e.g. "idp.writebuddy.org". That lets
 * OidcDiscoveryControllerHelper emit "https://idp.writebuddy.org" as
 * the issuer when the ATTR_HOST_ALIASED attribute is present, instead
 * of the path-based "https://idp.weldforge.org/t/{slug}" form.
 */
@Slf4j
@Component
@Order(Ordered.HIGHEST_PRECEDENCE + 11)
@RequiredArgsConstructor
public class HostAliasFilter extends OncePerRequestFilter {

    public static final String ATTR_HOST_ALIASED = "wf.tenant.hostAliased";
    public static final String ATTR_TENANT_SLUG  = "wf.tenant.slug";

    private static final Set<String> REWRITE_PREFIXES = Set.of(
            "/.well-known/openid-configuration",
            "/oauth2/",
            "/saml2/idp/",
            "/pki/"
    );

    private final TenantHostRepository tenantHostRepository;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {
        String path = request.getRequestURI();
        if (path == null || path.startsWith("/t/") || !isRewriteCandidate(path)) {
            chain.doFilter(request, response);
            return;
        }
        String host = request.getServerName();
        if (host == null || host.isBlank()) {
            chain.doFilter(request, response);
            return;
        }

        TenantHost row = tenantHostRepository.findByHostIgnoreCase(host).orElse(null);
        if (row == null) {
            chain.doFilter(request, response);
            return;
        }

        String slug = row.getTenant().getSlug();
        String forwardTo = "/t/" + slug + path;

        request.setAttribute(ATTR_HOST_ALIASED, Boolean.TRUE);
        request.setAttribute(ATTR_TENANT_SLUG, slug);
        TenantContext.set(slug);

        log.debug("host_alias host={} -> tenant={} forward={}", host, slug, forwardTo);
        RequestDispatcher dispatcher = request.getRequestDispatcher(forwardTo);
        dispatcher.forward(request, response);
    }

    private boolean isRewriteCandidate(String path) {
        for (String prefix : REWRITE_PREFIXES) {
            if (path.equals(prefix) || path.startsWith(prefix)) return true;
        }
        return false;
    }
}
