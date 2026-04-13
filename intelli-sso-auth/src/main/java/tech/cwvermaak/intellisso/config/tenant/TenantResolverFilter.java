package tech.cwvermaak.intellisso.config.tenant;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Resolves the current tenant from the incoming request and stashes the slug
 * in {@link TenantContext}. Resolution order:
 *
 *   1. {@code X-Tenant-Slug} header
 *   2. {@code /t/{slug}/...} path prefix
 *   3. {@code tenant} query parameter (handy for OAuth2 redirects that can't carry headers)
 *   4. Fallback to {@code default} so single-tenant callers keep working
 *
 * Runs before the JWT filter so that downstream auth/resolution has the
 * tenant in scope.
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE + 10)
public class TenantResolverFilter extends OncePerRequestFilter {

    public static final String HEADER = "X-Tenant-Slug";
    public static final String QUERY_PARAM = "tenant";
    public static final String DEFAULT_TENANT = "default";

    private static final Pattern PATH_PREFIX = Pattern.compile("^/t/([a-z0-9][a-z0-9-]{0,62}[a-z0-9])(/|$)");

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

        String path = request.getRequestURI();
        if (path != null) {
            Matcher m = PATH_PREFIX.matcher(path);
            if (m.find()) return m.group(1);
        }

        String qp = request.getParameter(QUERY_PARAM);
        if (qp != null && !qp.isBlank()) return qp.trim().toLowerCase();

        return DEFAULT_TENANT;
    }
}
