package tech.cwvermaak.weldforge.config.tenant;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import tech.cwvermaak.weldforge.config.ApiProblem;
import tech.cwvermaak.weldforge.model.AdminRole;

import java.io.IOException;
import java.util.regex.Pattern;

/**
 * The admin API is for admins. Refuses any authenticated call to
 * {@code /api/admin/**} whose caller holds no admin role in the tenant the call
 * acts in.
 *
 * <p>Until this existed, {@code SecurityConfig} required only that the caller
 * be <i>authenticated</i>, and every signed-in end user is: their access token
 * carries the platform audience and {@code adm=NONE}. Whether an end user could
 * call an admin endpoint was therefore decided method by method, by whether its
 * service remembered to call {@code TenantAccessor.require*Admin()}. Several
 * did not -- role, environment and app-client CRUD, the audit log, payment
 * gateways and SAML metadata import (which fetches a caller-chosen URL) -- so a
 * self-registered user could, for example, rename a role they held to an
 * application's admin role and receive it in their next token (security review
 * 2026-11-15). The per-method checks remain; they decide READ_ONLY versus
 * TENANT_ADMIN, which this cannot.
 *
 * <p>Runs after {@link CrossTenantSelectorFilter}, so it judges the tenant the
 * call actually acts in, and uses {@link TenantAccessor#effectiveRole} -- the
 * same resolution the selector uses, admin memberships included -- so no caller
 * with any real admin authority is refused here.
 *
 * <p>One exemption: {@code /api/admin/users/{id}/role-grants}, which a service
 * account holding only a role-grant prefix (adminRole NONE) is meant to call.
 * {@code RoleGrantService} authorises that path itself and refuses everyone
 * else.
 *
 * <p>Matched on the decoded servlet path as well as the raw URI: Spring MVC
 * routes {@code /api/%61dmin/roles} to the same controller, and a gate keyed on
 * the raw URI alone would not see it.
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class AdminAreaGateFilter extends OncePerRequestFilter {

    private static final String ADMIN_PREFIX = "/api/admin/";
    private static final Pattern ROLE_GRANTS =
            Pattern.compile("^/api/admin/users/[^/]+/role-grants(/.*)?$");

    private final TenantAccessor tenantAccessor;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        String decoded = decodedPath(request);
        String raw = request.getRequestURI();
        boolean admin = decoded.startsWith(ADMIN_PREFIX) || (raw != null && raw.startsWith(ADMIN_PREFIX));
        // Unauthenticated callers fall through to Spring Security's 401.
        if (!admin || !authenticated()) {
            filterChain.doFilter(request, response);
            return;
        }
        if (ROLE_GRANTS.matcher(decoded).matches()) {
            filterChain.doFilter(request, response);
            return;
        }

        if (!callerRole().canRead()) {
            log.info("admin_area_refused path={} tenant={} user={} service_account={}",
                    decoded, TenantContext.get(), TenantContext.getActorUserId(),
                    TenantContext.getActorServiceAccountId());
            ApiProblem.write(response, ApiProblem.body(HttpStatus.FORBIDDEN, "admin_role_required",
                    "This endpoint requires an admin role in tenant '" + TenantContext.get() + "'", request));
            return;
        }
        filterChain.doFilter(request, response);
    }

    private AdminRole callerRole() {
        if (TenantContext.isSuperAdmin()) return AdminRole.SUPER_ADMIN;
        Long tenantId = TenantContext.getTenantId();
        AdminRole role = tenantId != null ? tenantAccessor.effectiveRole(tenantId) : TenantContext.getAdminRole();
        return role == null ? AdminRole.NONE : role;
    }

    private static String decodedPath(HttpServletRequest request) {
        String servletPath = request.getServletPath();
        String pathInfo = request.getPathInfo();
        String path = (servletPath == null ? "" : servletPath) + (pathInfo == null ? "" : pathInfo);
        return path.isEmpty() && request.getRequestURI() != null ? request.getRequestURI() : path;
    }

    private static boolean authenticated() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        return auth != null && auth.isAuthenticated() && !(auth instanceof AnonymousAuthenticationToken);
    }
}
