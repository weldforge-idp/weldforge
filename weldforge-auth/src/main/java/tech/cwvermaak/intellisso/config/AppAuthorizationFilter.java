package tech.cwvermaak.intellisso.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.filter.OncePerRequestFilter;
import tech.cwvermaak.intellisso.config.tenant.TenantContext;
import tech.cwvermaak.intellisso.model.AdminRole;
import tech.cwvermaak.intellisso.model.AppClient;
import tech.cwvermaak.intellisso.model.ServiceAccount;
import tech.cwvermaak.intellisso.repository.AppClientRepository;
import tech.cwvermaak.intellisso.repository.ServiceAccountRepository;
import tech.cwvermaak.intellisso.service.security.ApiKeyHasher;

import java.io.IOException;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Authenticates callers presenting an API key or service-account token in
 * the {@code x-app-authorization} header (PRD TOK-01/02/03).
 *
 * <p>Two identity types live on the same header:
 * <ul>
 *   <li>{@code wf_live_*} — {@link AppClient} API key, hashed lookup, no
 *       admin role, enforces optional {path, methods} scopes.
 *   <li>{@code wf_svc_*} — {@link ServiceAccount} token, hashed lookup,
 *       populates {@link AdminRole} in {@link TenantContext}, and fails if
 *       expired.
 * </ul>
 *
 * <p>Legacy plaintext keys from before V23 are still accepted via a
 * fallback lookup against {@code api_key} so unrotated integrations keep
 * working. Rotating the key swaps the row to hash-only storage.
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class AppAuthorizationFilter extends OncePerRequestFilter {

    private final AppClientRepository appClientRepository;
    private final ServiceAccountRepository serviceAccountRepository;

    private static final AntPathMatcher PATH_MATCHER = new AntPathMatcher();

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        String path = request.getRequestURI();

        // Public paths — skip the app-authorization header check.
        // NOTE: /v3/api-docs, /swagger-ui and /swagger-ui.html are
        // intentionally NOT listed here. SECURITY_AUDIT_2026-04-15.md
        // MEDIUM-1 — the OpenAPI spec and interactive Swagger UI were
        // previously anonymously reachable, which handed an attacker a
        // complete map of the API. They now require a valid app-client
        // key. Internal callers via admin.weldforge.org still work
        // because nginx injects the header; external scanners do not.
        if (path.startsWith("/login")
                || path.startsWith("/oauth2")
                || path.equals("/error")
                || path.startsWith("/actuator/")
                || path.startsWith("/t/")          // per-tenant OIDC + SAML IdP
                || path.startsWith("/saml2/")      // SAML SP login
                || path.startsWith("/scim/v2/")    // SCIM (has its own auth filter)
                || path.startsWith("/webjars/")) {
            filterChain.doFilter(request, response);
            return;
        }

        String header = request.getHeader("x-app-authorization");
        if (header == null || header.isBlank()) {
            deny(response, "Missing or invalid x-app-authorization header");
            return;
        }

        // Service-account path: wf_svc_* → carries admin role.
        if (header.startsWith(ApiKeyHasher.SERVICE_ACCOUNT_PREFIX)) {
            Optional<ServiceAccount> saOpt =
                    serviceAccountRepository.findByTokenHashAndEnabledTrue(ApiKeyHasher.hash(header));
            if (saOpt.isEmpty()) {
                deny(response, "Invalid service account token");
                return;
            }
            ServiceAccount sa = saOpt.get();
            if (sa.getExpiresAt() != null && sa.getExpiresAt().isBefore(LocalDateTime.now())) {
                deny(response, "Service account token expired");
                return;
            }
            if (sa.getTenant() != null) {
                TenantContext.set(sa.getTenant().getSlug(), sa.getTenant().getId(), sa.getAdminRole());
            }
            // Service accounts get a SecurityContext authentication so the
            // controller layer's standard @PreAuthorize / tenantAccessor
            // guards treat them as first-class admin callers.
            var authn = new UsernamePasswordAuthenticationToken(
                    "svc:" + sa.getId(),
                    null,
                    List.of(new SimpleGrantedAuthority("ROLE_SERVICE_ACCOUNT")));
            SecurityContextHolder.getContext().setAuthentication(authn);
            filterChain.doFilter(request, response);
            return;
        }

        // App-client path: wf_live_* — hashed lookup only. The plaintext
        // fallback that existed as a V23 grace-period helper was removed
        // following SECURITY_AUDIT_2026-04-15.md CRITICAL-1: any legacy
        // unhashed row in app_clients is treated as revoked. Rotate stale
        // keys through POST /api/admin/app-clients/{id}/rotate.
        Optional<AppClient> clientOpt =
                appClientRepository.findByApiKeyHashAndEnabledTrue(ApiKeyHasher.hash(header));
        if (clientOpt.isEmpty()) {
            deny(response, "Missing or invalid x-app-authorization header");
            return;
        }

        AppClient client = clientOpt.get();
        if (!isWithinScope(client, request)) {
            deny(response, "API key not authorised for this path/method");
            return;
        }
        if (client.getTenant() != null) {
            TenantContext.set(client.getTenant().getSlug(), client.getTenant().getId(), false);
        }
        filterChain.doFilter(request, response);
    }

    /**
     * PRD TOK-02. When {@code scopes} is empty the key has no restriction
     * (backward-compat default). Otherwise the request must match at least
     * one {path, methods} entry.
     */
    @SuppressWarnings("unchecked")
    private boolean isWithinScope(AppClient client, HttpServletRequest request) {
        List<Map<String, Object>> scopes = client.getScopes();
        if (scopes == null || scopes.isEmpty()) return true;

        String reqPath = request.getRequestURI();
        String reqMethod = request.getMethod().toUpperCase();

        for (Map<String, Object> scope : scopes) {
            Object pathPattern = scope.get("path");
            if (!(pathPattern instanceof String p)) continue;
            if (!PATH_MATCHER.match(p, reqPath)) continue;

            Object methods = scope.get("methods");
            if (methods == null) return true;
            if (methods instanceof List<?> list) {
                boolean any = list.stream()
                        .filter(m -> m != null)
                        .map(Object::toString)
                        .map(String::toUpperCase)
                        .anyMatch(m -> m.equals("*") || m.equals(reqMethod));
                if (any) return true;
            }
        }
        return false;
    }

    private static void deny(HttpServletResponse response, String msg) throws IOException {
        response.setStatus(HttpServletResponse.SC_FORBIDDEN);
        response.getWriter().write(msg);
    }
}
