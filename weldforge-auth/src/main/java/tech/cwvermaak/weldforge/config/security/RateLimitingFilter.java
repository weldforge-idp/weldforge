package tech.cwvermaak.weldforge.config.security;

import io.github.bucket4j.ConsumptionProbe;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import tech.cwvermaak.weldforge.service.security.RateLimitingService;
import tech.cwvermaak.weldforge.service.security.RateLimitingService.Bucket4jEndpoint;

import java.io.IOException;
import java.util.Map;

/**
 * Applies rate limits to the sensitive auth endpoints. Buckets are keyed
 * by the caller's IP (honoring {@code X-Forwarded-For}), so an attacker
 * running a credential stuffing run from one host hits the cap quickly
 * without affecting other traffic.
 *
 * Rejections return HTTP 429 with {@code Retry-After} so clients can back
 * off politely.
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class RateLimitingFilter extends OncePerRequestFilter {

    private static final Map<String, Bucket4jEndpoint> ROUTES = Map.of(
            "/api/auth/login",                Bucket4jEndpoint.LOGIN,
            "/api/auth/register",             Bucket4jEndpoint.REGISTER,
            "/api/auth/mfa/verify",           Bucket4jEndpoint.MFA_VERIFY,
            // B-AUTH-3: throttle account-recovery + SMS-send (email-abuse /
            // SendGrid-quota exhaustion / SMS toll-fraud).
            "/api/auth/forgot-password",      Bucket4jEndpoint.RECOVERY,
            "/api/auth/reset-password",       Bucket4jEndpoint.RECOVERY,
            "/api/auth/resend-verification",  Bucket4jEndpoint.RECOVERY,
            "/api/auth/mfa/sms/send",         Bucket4jEndpoint.RECOVERY
    );

    private final RateLimitingService rateLimitingService;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {
        Bucket4jEndpoint endpoint = ROUTES.get(request.getRequestURI());
        if (endpoint == null) {
            chain.doFilter(request, response);
            return;
        }

        String key = clientIp(request);
        ConsumptionProbe probe = rateLimitingService.tryConsume(endpoint, key);

        if (!probe.isConsumed()) {
            long retryAfterSeconds = Math.max(1, probe.getNanosToWaitForRefill() / 1_000_000_000L);
            log.warn("Rate limit exceeded endpoint={} ip={} retry_after_s={}",
                    endpoint, key, retryAfterSeconds);
            response.setStatus(429);
            response.setHeader("Retry-After", String.valueOf(retryAfterSeconds));
            response.setContentType("application/json");
            response.getWriter().write(
                    "{\"error\":\"too_many_requests\",\"retryAfterSeconds\":" + retryAfterSeconds + "}");
            return;
        }

        response.setHeader("X-RateLimit-Remaining", String.valueOf(probe.getRemainingTokens()));
        chain.doFilter(request, response);
    }

    private static String clientIp(HttpServletRequest request) {
        // B-AUTH-1: trust ONLY the address resolved by Tomcat's RemoteIpValve
        // (server.forward-headers-strategy=native), which walks X-Forwarded-For
        // right-to-left skipping trusted internal proxies and lands on the real
        // client. Parsing the raw header here and taking the LEFTMOST token
        // trusted an attacker-supplied value — a spoofed `X-Forwarded-For:
        // <random>` minted a fresh per-IP bucket on every request, defeating the
        // rate limiter. getRemoteAddr() is never client-spoofable.
        return request.getRemoteAddr();
    }
}
