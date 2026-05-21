package tech.cwvermaak.weldforge.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Set;

/**
 * Hard-enforces the implicit invariant that every mutating
 * {@code /api/auth/**} request takes {@code application/json}. Returns
 * 415 Unsupported Media Type for anything else (form-encoded,
 * multipart, plain text, missing content-type on a non-empty body).
 *
 * <h2>Why this matters</h2>
 *
 * <p>The session cookie is scoped to the public base domain
 * ({@code Domain=sso.weldforge.org}) so it survives the
 * subdomain-login → apex-OIDC-consent bounce. That broadened scope
 * means a hostile-but-trusted sibling tenant subdomain shares the
 * cookie with its siblings. Two layers defend against the implied
 * CSRF surface:</p>
 *
 * <ol>
 *   <li>{@code JwtAuthenticationFilter} refuses a JWT whose
 *       {@code tenant_id} doesn't match the request's implicit
 *       tenant — so an authenticated forged request would be
 *       treated as anonymous.</li>
 *   <li><b>This filter</b> — refuses to even parse a non-JSON body
 *       on the cookie-consuming endpoints. Browsers can't
 *       cross-origin-POST {@code application/json} without a
 *       preflight (CORS will then reject), but they CAN
 *       cross-origin-POST form-encoded bodies via a plain HTML
 *       form. Forcing JSON closes that classic form-CSRF path.</li>
 * </ol>
 *
 * <p>The {@code /login/**} hosted auth form (Spring HTML renderer)
 * is deliberately NOT covered — it accepts
 * {@code application/x-www-form-urlencoded} because that's what a
 * &lt;form&gt; element posts. That path is unauthenticated and
 * triggers a fresh sign-in; CSRF on it would just submit credentials
 * the attacker doesn't have.</p>
 *
 * <p>See {@code docs/auth-url-spec.md} §"Cookies — defence-in-depth".</p>
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE + 30)
@Slf4j
public class AuthJsonContentTypeFilter extends OncePerRequestFilter {

    private static final String AUTH_PATH_PREFIX = "/api/auth/";

    private static final Set<String> MUTATING_METHODS = Set.of("POST", "PUT", "PATCH", "DELETE");

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {
        if (shouldEnforce(request) && !isJsonOrEmpty(request)) {
            log.warn("auth_content_type_rejected method={} path={} content_type={} ip={}",
                    request.getMethod(), request.getRequestURI(),
                    request.getContentType(), request.getRemoteAddr());
            response.setStatus(HttpStatus.UNSUPPORTED_MEDIA_TYPE.value());
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            response.getWriter().write(
                    "{\"error\":\"unsupported_media_type\","
                  + "\"message\":\"/api/auth/** requires Content-Type: application/json\"}");
            return;
        }
        chain.doFilter(request, response);
    }

    private static boolean shouldEnforce(HttpServletRequest request) {
        String path = request.getRequestURI();
        if (path == null || !path.startsWith(AUTH_PATH_PREFIX)) return false;
        return MUTATING_METHODS.contains(request.getMethod());
    }

    private static boolean isJsonOrEmpty(HttpServletRequest request) {
        String type = request.getContentType();
        long len = request.getContentLengthLong();
        // No Content-Type header is acceptable only when the request
        // also has no body. DELETE without a body is the typical case;
        // a body-bearing request without a declared type can't be safely
        // routed and should be refused here rather than at @RequestBody.
        if (type == null) return len <= 0;
        // Strip charset/boundary parameters: "application/json; charset=UTF-8".
        int semi = type.indexOf(';');
        String mediaType = (semi == -1 ? type : type.substring(0, semi)).trim().toLowerCase();
        return MediaType.APPLICATION_JSON_VALUE.equals(mediaType)
                || mediaType.equals("application/json-patch+json")
                || mediaType.equals("application/merge-patch+json");
    }
}
