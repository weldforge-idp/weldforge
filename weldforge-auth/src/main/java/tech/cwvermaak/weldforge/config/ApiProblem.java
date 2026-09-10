package tech.cwvermaak.weldforge.config;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;

import java.io.IOException;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * RFC 9457 Problem Details for the {@code /api/**} surface (CONF-7.3).
 *
 * <p>Every error there is {@code application/problem+json} carrying the five
 * standard members -- {@code type}, {@code title}, {@code status},
 * {@code detail}, {@code instance} -- so a client writes its error handling
 * once. The members this API returned before ({@code error}, {@code message},
 * {@code timestamp}, {@code path}, plus per-error extras such as
 * {@code reasons}) stay alongside them as extension members, which RFC 9457
 * §3.2 permits: the admin portal and the Tech Metropolis proxies parse those,
 * and changing the shape under them would break every error path at once.
 *
 * <p>Scope is {@code /api/**} only. The OAuth 2.0, OIDC and SCIM endpoints
 * answer in the error formats their own specifications require
 * ({@code {error, error_description}}, SCIM error responses), and a client of
 * those protocols must not be handed something else.
 *
 * <p>{@code type} is a {@code tag:} URI (RFC 4151): stable and unique per
 * error code, and explicitly not something to dereference.
 */
public final class ApiProblem {

    public static final String TYPE_PREFIX = "tag:weldforge.org,2026:problem:";

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private ApiProblem() {}

    /** True for requests on the surface that answers in Problem Details. */
    public static boolean appliesTo(HttpServletRequest request) {
        String uri = request.getRequestURI();
        return uri != null && uri.startsWith("/api/");
    }

    /**
     * A problem document: the RFC 9457 members first, then the legacy ones.
     *
     * @param code    the stable machine code, e.g. {@code validation_error};
     *                it becomes both the {@code type} suffix and {@code error}
     * @param message the human explanation of this occurrence; both
     *                {@code detail} and the legacy {@code message}
     */
    public static Map<String, Object> body(HttpStatus status, String code, String message,
                                           HttpServletRequest request) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("type", TYPE_PREFIX + code);
        body.put("title", status.getReasonPhrase());
        body.put("status", status.value());
        body.put("detail", message);
        body.put("instance", request.getRequestURI());
        body.put("error", code);
        body.put("message", message);
        body.put("timestamp", Instant.now().toString());
        body.put("path", request.getRequestURI());
        return body;
    }

    /** Write a problem straight to the servlet response, for filters outside MVC. */
    public static void write(HttpServletResponse response, Map<String, Object> body) throws IOException {
        response.setStatus((Integer) body.get("status"));
        response.setContentType(MediaType.APPLICATION_PROBLEM_JSON_VALUE);
        response.setCharacterEncoding("UTF-8");
        try {
            response.getWriter().write(MAPPER.writeValueAsString(body));
        } catch (JsonProcessingException e) {
            throw new IOException("could not serialise problem details", e);
        }
    }
}
