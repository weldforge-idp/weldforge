package tech.cwvermaak.intellisso.config.logging;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.MDC;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import tech.cwvermaak.intellisso.config.tenant.TenantContext;

import java.io.IOException;
import java.util.UUID;

/**
 * Populates the SLF4J MDC so every log line emitted during a request carries:
 *
 *   request_id   correlation id (from X-Request-Id header or freshly minted)
 *   tenant       current tenant slug (may come from header, path, api key, or JWT)
 *   actor        authenticated user email, if any
 *   super_admin  "true" when the caller is a super admin
 *
 * Runs late enough that the tenant resolver and JWT filter have already run,
 * and still clears the MDC in {@code finally} so a pooled thread cannot leak
 * state between requests.
 */
@Component
public class MdcEnrichmentFilter extends OncePerRequestFilter {

    public static final String MDC_REQUEST_ID  = "request_id";
    public static final String MDC_TENANT      = "tenant";
    public static final String MDC_ACTOR       = "actor";
    public static final String MDC_SUPER_ADMIN = "super_admin";

    public static final String HEADER_REQUEST_ID = "X-Request-Id";

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {
        try {
            String requestId = request.getHeader(HEADER_REQUEST_ID);
            if (requestId == null || requestId.isBlank()) {
                requestId = UUID.randomUUID().toString();
            }
            MDC.put(MDC_REQUEST_ID, requestId);
            response.setHeader(HEADER_REQUEST_ID, requestId);

            String tenant = TenantContext.get();
            if (tenant != null) MDC.put(MDC_TENANT, tenant);

            MDC.put(MDC_SUPER_ADMIN, Boolean.toString(TenantContext.isSuperAdmin()));

            Authentication auth = SecurityContextHolder.getContext().getAuthentication();
            if (auth != null && auth.getPrincipal() instanceof String principal && !principal.isBlank()) {
                MDC.put(MDC_ACTOR, principal);
            }

            chain.doFilter(request, response);
        } finally {
            MDC.remove(MDC_REQUEST_ID);
            MDC.remove(MDC_TENANT);
            MDC.remove(MDC_ACTOR);
            MDC.remove(MDC_SUPER_ADMIN);
        }
    }
}
