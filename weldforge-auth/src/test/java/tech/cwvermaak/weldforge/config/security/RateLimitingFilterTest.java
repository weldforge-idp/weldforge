package tech.cwvermaak.weldforge.config.security;

import io.github.bucket4j.ConsumptionProbe;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import tech.cwvermaak.weldforge.service.security.RateLimitingService;
import tech.cwvermaak.weldforge.service.security.RateLimitingService.Bucket4jEndpoint;

import java.io.PrintWriter;
import java.io.StringWriter;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

/**
 * B-AUTH-3: the account-recovery and SMS-send endpoints are rate-limited
 * (RECOVERY bucket), and a depleted bucket yields a 429.
 */
class RateLimitingFilterTest {

    private RateLimitingService service;
    private RateLimitingFilter filter;

    @BeforeEach
    void setUp() {
        service = mock(RateLimitingService.class);
        filter = new RateLimitingFilter(service);
    }

    private static HttpServletRequest req(String uri) {
        HttpServletRequest r = mock(HttpServletRequest.class);
        when(r.getRequestURI()).thenReturn(uri);
        when(r.getRemoteAddr()).thenReturn("203.0.113.7");
        return r;
    }

    @Test
    @DisplayName("recovery + SMS-send endpoints route to the RECOVERY bucket")
    void recoveryEndpointsAreLimited() throws Exception {
        when(service.tryConsume(any(), any())).thenReturn(ConsumptionProbe.consumed(4L, 0L));
        FilterChain chain = mock(FilterChain.class);

        for (String uri : new String[]{
                "/api/auth/forgot-password", "/api/auth/reset-password",
                "/api/auth/resend-verification", "/api/auth/mfa/sms/send"}) {
            filter.doFilterInternal(req(uri), mock(HttpServletResponse.class), chain);
        }

        verify(service, times(4)).tryConsume(eq(Bucket4jEndpoint.RECOVERY), any());
    }

    @Test
    @DisplayName("an unlisted endpoint is not rate-limited")
    void unlistedEndpointPassesThrough() throws Exception {
        FilterChain chain = mock(FilterChain.class);

        filter.doFilterInternal(req("/api/auth/profile"), mock(HttpServletResponse.class), chain);

        verify(service, never()).tryConsume(any(), any());
        verify(chain).doFilter(any(), any());
    }

    @Test
    @DisplayName("a depleted bucket returns 429 and does not continue the chain")
    void depletedBucketReturns429() throws Exception {
        when(service.tryConsume(eq(Bucket4jEndpoint.RECOVERY), any()))
                .thenReturn(ConsumptionProbe.rejected(0L, 1_000_000_000L, 1_000_000_000L));
        FilterChain chain = mock(FilterChain.class);
        HttpServletResponse res = mock(HttpServletResponse.class);
        when(res.getWriter()).thenReturn(new PrintWriter(new StringWriter()));

        filter.doFilterInternal(req("/api/auth/forgot-password"), res, chain);

        verify(res).setStatus(429);
        verify(res).setHeader(eq("Retry-After"), any());
        verify(chain, never()).doFilter(any(), any());
    }
}
