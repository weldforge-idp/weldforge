package tech.cwvermaak.intellisso.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import tech.cwvermaak.intellisso.repository.AppClientRepository;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class AppAuthorizationFilter extends OncePerRequestFilter {

    private final AppClientRepository appClientRepository;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        String path = request.getRequestURI();

        // Skip filter for public OAuth paths and login
        if (path.startsWith("/login") || path.startsWith("/oauth2") || path.equals("/error") || path.startsWith("/actuator/")) {
            filterChain.doFilter(request, response);
            return;
        }

        String authHeader = request.getHeader("x-app-authorization");

        if (authHeader != null && appClientRepository.findByApiKeyAndEnabledTrue(authHeader).isPresent()) {
            filterChain.doFilter(request, response);
            return;
        }

        response.setStatus(HttpServletResponse.SC_FORBIDDEN);
        response.getWriter().write("Missing or invalid x-app-authorization header");
    }
}