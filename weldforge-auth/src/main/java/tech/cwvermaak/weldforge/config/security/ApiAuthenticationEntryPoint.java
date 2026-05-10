package tech.cwvermaak.weldforge.config.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Returns a JSON 401 for unauthenticated requests on the /api/** surface.
 *
 * Without this, Spring's default delegating entry point (installed by
 * oauth2Login / saml2Login) issues a 302 to /login for any unauthenticated
 * API call. The SPA's HttpClient follows that redirect, lands on /login,
 * gets the SPA index.html back (nginx try_files fallback), and tries to
 * parse the HTML as JSON — surfaces in the portal as
 * "Http failure during parsing for https://sso.weldforge.org/login".
 *
 * The body shape mirrors {@link tech.cwvermaak.weldforge.config.GlobalExceptionHandler}
 * so clients can rely on one error contract across every /api/** response.
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class ApiAuthenticationEntryPoint implements AuthenticationEntryPoint {

    private final ObjectMapper mapper;

    @Override
    public void commence(HttpServletRequest request,
                         HttpServletResponse response,
                         AuthenticationException authException) throws IOException {
        log.debug("api unauthenticated {} {} → 401 ({})",
                request.getMethod(), request.getRequestURI(), authException.getMessage());

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("error", "unauthorized");
        body.put("message", "Authentication required");
        body.put("timestamp", Instant.now().toString());
        body.put("path", request.getRequestURI());

        response.setStatus(HttpStatus.UNAUTHORIZED.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding("UTF-8");
        mapper.writeValue(response.getWriter(), body);
    }
}
