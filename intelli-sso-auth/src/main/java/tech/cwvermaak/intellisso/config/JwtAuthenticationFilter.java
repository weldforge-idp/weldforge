package tech.cwvermaak.intellisso.config;

import io.jsonwebtoken.Claims;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import tech.cwvermaak.intellisso.config.tenant.TenantContext;
import tech.cwvermaak.intellisso.model.AdminRole;
import tech.cwvermaak.intellisso.repository.UserRepository;
import tech.cwvermaak.intellisso.service.JwtService;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    /** Cookie name used for browser-redirect OIDC flows. */
    public static final String SESSION_COOKIE = "wf_session";

    private final JwtService jwtService;
    private final UserRepository userRepository;

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
            if (userOpt.isPresent() && userOpt.get().getTokenVersion() > tokenVersion) {
                filterChain.doFilter(request, response);
                return;
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

        if (slug != null && !slug.isBlank()) {
            TenantContext.set(slug, tid, adminRole);
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
