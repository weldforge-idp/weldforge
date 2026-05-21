package tech.cwvermaak.weldforge.config;

import io.jsonwebtoken.Claims;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import tech.cwvermaak.weldforge.config.tenant.TenantContext;
import tech.cwvermaak.weldforge.config.tenant.TenantResolverFilter;
import tech.cwvermaak.weldforge.model.AdminRole;
import tech.cwvermaak.weldforge.repository.TenantRepository;
import tech.cwvermaak.weldforge.repository.UserRepository;
import tech.cwvermaak.weldforge.service.JwtService;

import java.io.IOException;

@Component
@RequiredArgsConstructor
@Slf4j
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    /** Cookie name used for browser-redirect OIDC flows. */
    public static final String SESSION_COOKIE = "wf_session";

    private final JwtService jwtService;
    private final UserRepository userRepository;
    private final TenantRepository tenantRepository;
    private final TenantResolverFilter tenantResolver;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        // Look for the JWT in the Authorization header first (the API
        // path), then in the wf_session cookie (the browser-redirect path
        // used by OIDC). Either is acceptable; one is enough.
        String jwt = readBearer(request);
        if (jwt == null) jwt = readSessionCookie(request);
        if (jwt == null) {
            filterChain.doFilter(request, response);
            return;
        }
        if (!jwtService.isTokenValid(jwt)) {
            filterChain.doFilter(request, response);
            return;
        }

        Claims claims = jwtService.parse(jwt);

        // Reject non-access tokens (e.g. the short-lived mfa_challenge token
        // issued mid-login). Those must only be accepted by the MFA verify
        // endpoint, not authenticate arbitrary API calls.
        Object purpose = claims.get(JwtService.CLAIM_PURPOSE);
        if (purpose != null && !JwtService.PURPOSE_ACCESS.equals(purpose.toString())) {
            filterChain.doFilter(request, response);
            return;
        }

        String email = claims.getSubject();
        Object tenantSlug = claims.get(JwtService.CLAIM_TENANT_SLUG);
        Object tenantId   = claims.get(JwtService.CLAIM_TENANT_ID);
        Object superAdmin = claims.get(JwtService.CLAIM_SUPER_ADMIN);
        Object adminRoleClaim = claims.get(JwtService.CLAIM_ADMIN_ROLE);
        Integer tokenVersion = jwtService.extractTokenVersion(claims);

        // Session revocation: if the token's version is older than the
        // user's current token_version, every outstanding access token was
        // invalidated (password change, admin reset, logout-all). Refuse.
        if (tokenVersion != null && tenantSlug != null) {
            var userOpt = userRepository.findByTenant_SlugAndEmailIgnoreCase(tenantSlug.toString(), email);
            if (userOpt.isPresent()) {
                if (userOpt.get().getTokenVersion() > tokenVersion) {
                    filterChain.doFilter(request, response);
                    return;
                }
                // Actor identity — the cross-tenant selector (X-WF-Tenant)
                // resolves admin memberships against this user id.
                TenantContext.setActorUser(userOpt.get().getId());
            }
        }

        // The JWT is authoritative for *who* the caller is and *which tenant*
        // they belong to. We deliberately overwrite whatever the pre-auth
        // resolver set from the X-Tenant-Slug header: a logged-in user must
        // not be able to fake cross-tenant access by swapping headers.
        String slug = tenantSlug == null ? null : tenantSlug.toString();
        Long   tid  = null;
        if (tenantId instanceof Number n) tid = n.longValue();
        else if (tenantId instanceof String s && !s.isBlank()) {
            try { tid = Long.valueOf(s); } catch (NumberFormatException ignored) {}
        }
        boolean sa = Boolean.TRUE.equals(superAdmin)
                || "true".equalsIgnoreCase(String.valueOf(superAdmin));

        AdminRole adminRole;
        if (adminRoleClaim != null && !adminRoleClaim.toString().isBlank()) {
            try {
                adminRole = AdminRole.valueOf(adminRoleClaim.toString());
            } catch (IllegalArgumentException e) {
                adminRole = sa ? AdminRole.SUPER_ADMIN : AdminRole.NONE;
            }
        } else {
            // Back-compat: older tokens without the adm claim use the legacy sa bool.
            adminRole = sa ? AdminRole.SUPER_ADMIN : AdminRole.NONE;
        }

        // Cross-tenant cookie safety. The wf_session cookie is scoped to the
        // public base domain so it survives the per-tenant-subdomain →
        // apex-OIDC-consent bounce. The browser will therefore send a tenant
        // A session cookie to tenant B's subdomain. Without this check, the
        // user would be silently authenticated as their home tenant against
        // tenant B's UI / API — every per-tenant isolation guarantee in
        // SECURITY_AUDIT_2026-04-15 would collapse.
        //
        // The implicit tenant (Host subdomain or /t/{slug}/ path prefix) is
        // the request's *target* — distinct from the X-Tenant-Slug header,
        // which is the explicit cross-tenant channel reserved for super-
        // admins. We refuse to authenticate the JWT when its tenant_id
        // doesn't match the implicit target. Super-admins are exempt — they
        // legitimately cross tenant boundaries via the picker.
        if (slug != null && !slug.isBlank() && !sa) {
            String implicit = tenantResolver.implicitTenantSlug(request);
            if (implicit != null && !implicit.equalsIgnoreCase(slug)) {
                log.warn("jwt_tenant_mismatch jwt_tenant={} request_tenant={} path={} host={}",
                        slug, implicit, request.getRequestURI(), request.getServerName());
                filterChain.doFilter(request, response);
                return;
            }
        }

        if (slug != null && !slug.isBlank()) {
            TenantContext.set(slug, tid, adminRole);
        }

        // Super-admin tenant impersonation: a SUPER_ADMIN can scope the
        // request to a tenant other than their JWT's home tenant by
        // sending an explicit X-Tenant-Slug header. This drives the
        // admin-portal "select tenant" dropdown so a super-admin can
        // manage users/roles in other tenants without re-issuing a JWT.
        // The privilege is gated strictly on the JWT's `sa` claim — any
        // non-super-admin sending the same header keeps their home
        // tenant (the original "JWT is authoritative" rule), so the
        // header cannot be used to fake cross-tenant access.
        if (sa) {
            String overrideSlug = request.getHeader(TenantResolverFilter.HEADER);
            if (overrideSlug != null && !overrideSlug.isBlank()) {
                String normalized = overrideSlug.trim().toLowerCase();
                if (slug == null || !normalized.equals(slug)) {
                    tenantRepository.findBySlug(normalized).ifPresent(t -> {
                        TenantContext.set(t.getSlug(), t.getId(), AdminRole.SUPER_ADMIN);
                        log.info("super_admin_tenant_override actor={} home={} acting={}",
                                email, slug, t.getSlug());
                    });
                }
            }
        }

        UsernamePasswordAuthenticationToken authToken =
                new UsernamePasswordAuthenticationToken(email, null, null);
        authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
        SecurityContextHolder.getContext().setAuthentication(authToken);

        filterChain.doFilter(request, response);
    }

    private static String readBearer(HttpServletRequest request) {
        String header = request.getHeader("Authorization");
        if (header == null || !header.startsWith("Bearer ")) return null;
        return header.substring(7);
    }

    private static String readSessionCookie(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        if (cookies == null) return null;
        for (Cookie c : cookies) {
            if (SESSION_COOKIE.equals(c.getName())) return c.getValue();
        }
        return null;
    }
}
