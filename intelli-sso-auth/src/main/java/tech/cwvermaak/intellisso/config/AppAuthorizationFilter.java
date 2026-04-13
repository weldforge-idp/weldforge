package tech.cwvermaak.intellisso.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import tech.cwvermaak.intellisso.config.tenant.TenantContext;
import tech.cwvermaak.intellisso.model.AppClient;
import tech.cwvermaak.intellisso.repository.AppClientRepository;

import java.io.IOException;
import java.util.Optional;

@Component
@RequiredArgsConstructor
public class AppAuthorizationFilter extends OncePerRequestFilter {

    private final AppClientRepository appClientRepository;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        String path = request.getRequestURI();

        // Public paths — skip the app-authorization header check.
        // These are secured by Spring Security's permitAll rules and
        // their own filter chains (SCIM bearer token, SAML flows, etc.).
        if (path.startsWith("/login")
                || path.startsWith("/oauth2")
                || path.equals("/error")
                || path.startsWith("/actuator/")
                || path.startsWith("/t/")          // per-tenant OIDC + SAML IdP
                || path.startsWith("/saml2/")      // SAML SP login
                || path.startsWith("/scim/v2/")    // SCIM (has its own auth filter)
                || path.startsWith("/v3/api-docs") // OpenAPI spec
                || path.startsWith("/swagger-ui")  // Swagger UI
                || path.equals("/swagger-ui.html")
                || path.startsWith("/webjars/")) {
            filterChain.doFilter(request, response);
            return;
        }

        String authHeader = request.getHeader("x-app-authorization");
        if (authHeader != null) {
            Optional<AppClient> client = appClientRepository.findByApiKeyAndEnabledTrue(authHeader);
            if (client.isPresent()) {
                // Bind the request to the api key's owning tenant so every
                // downstream query is tenant-scoped. A JWT, if also present,
                // will overwrite this in JwtAuthenticationFilter — that is
                // fine because the JWT identifies the same caller.
                AppClient c = client.get();
                if (c.getTenant() != null) {
                    TenantContext.set(c.getTenant().getSlug(), c.getTenant().getId(), false);
                }
                filterChain.doFilter(request, response);
                return;
            }
        }

        response.setStatus(HttpServletResponse.SC_FORBIDDEN);
        response.getWriter().write("Missing or invalid x-app-authorization header");
    }
}
