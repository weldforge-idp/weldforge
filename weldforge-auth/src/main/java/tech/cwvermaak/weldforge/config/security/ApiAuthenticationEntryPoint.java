package tech.cwvermaak.weldforge.config.security;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;
import tech.cwvermaak.weldforge.config.ApiProblem;

import java.io.IOException;

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
 * The body is the same RFC 9457 problem document as every other /api/**
 * error ({@link ApiProblem}, CONF-7.3), so clients rely on one contract.
 */
@Component
@Slf4j
public class ApiAuthenticationEntryPoint implements AuthenticationEntryPoint {

    @Override
    public void commence(HttpServletRequest request,
                         HttpServletResponse response,
                         AuthenticationException authException) throws IOException {
        log.debug("api unauthenticated {} {} → 401 ({})",
                request.getMethod(), request.getRequestURI(), authException.getMessage());

        ApiProblem.write(response, ApiProblem.body(
                HttpStatus.UNAUTHORIZED, "unauthorized", "Authentication required", request));
    }
}
