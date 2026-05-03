package tech.cwvermaak.weldforge.config.scim;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import tech.cwvermaak.weldforge.config.tenant.TenantContext;
import tech.cwvermaak.weldforge.model.AppClient;
import tech.cwvermaak.weldforge.repository.AppClientRepository;
import tech.cwvermaak.weldforge.service.security.ApiKeyHasher;

import java.io.IOException;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Authenticates SCIM clients via {@code Authorization: Bearer <api-key>}
 * against the existing {@code app_clients} table. The path under
 * {@code /scim/v2/{slug}/...} carries the tenant slug — we cross-check
 * that the API key the caller presents actually belongs to that tenant
 * so a leaked token can never be used against a different tenant.
 *
 * Lives outside the Security chain (registered as a plain filter via
 * {@link ScimSecurityConfig}) and only fires on {@code /scim/v2/...} URLs.
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class ScimAuthenticationFilter extends OncePerRequestFilter {

    private static final Pattern SCIM_PATH = Pattern.compile("^/scim/v2/([a-z0-9][a-z0-9-]{0,62}[a-z0-9])(/.*)?$");

    private final AppClientRepository appClientRepository;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {
        String path = request.getRequestURI();
        Matcher m = SCIM_PATH.matcher(path);
        if (!m.matches()) {
            chain.doFilter(request, response);
            return;
        }
        String urlSlug = m.group(1);

        String header = request.getHeader("Authorization");
        if (header == null || !header.startsWith("Bearer ")) {
            unauthorised(response, "missing_bearer_token");
            return;
        }
        String apiKey = header.substring(7).trim();

        // Hashed lookup only. The earlier plaintext fallback was
        // removed as part of SECURITY_AUDIT_2026-04-15.md CRITICAL-1
        // — legacy unhashed rows are treated as revoked.
        Optional<AppClient> client =
                appClientRepository.findByApiKeyHashAndEnabledTrue(ApiKeyHasher.hash(apiKey));
        if (client.isEmpty()) {
            unauthorised(response, "invalid_token");
            return;
        }
        AppClient c = client.get();
        if (c.getTenant() == null || !urlSlug.equals(c.getTenant().getSlug())) {
            log.warn("SCIM token tenant mismatch: token_tenant={} url_tenant={}",
                    c.getTenant() == null ? "<none>" : c.getTenant().getSlug(), urlSlug);
            unauthorised(response, "tenant_mismatch");
            return;
        }

        // Bind the request to the api key's tenant so the SCIM service's
        // tenant accessor lights up. Use a synthetic principal so audit
        // events have something to reference.
        TenantContext.set(c.getTenant().getSlug(), c.getTenant().getId(), false);
        UsernamePasswordAuthenticationToken auth =
                new UsernamePasswordAuthenticationToken("scim:" + c.getClientName(), null, java.util.List.of());
        SecurityContextHolder.getContext().setAuthentication(auth);
        try {
            chain.doFilter(request, response);
        } finally {
            SecurityContextHolder.clearContext();
        }
    }

    private static void unauthorised(HttpServletResponse response, String code) throws IOException {
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setHeader("WWW-Authenticate", "Bearer error=\"" + code + "\"");
        response.setContentType("application/scim+json");
        response.getWriter().write(
                "{\"schemas\":[\"urn:ietf:params:scim:api:messages:2.0:Error\"],"
                + "\"status\":\"401\",\"detail\":\"" + code + "\"}");
    }
}
