package tech.cwvermaak.weldforge.config;

import jakarta.servlet.FilterChain;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import tech.cwvermaak.weldforge.repository.AppClientRepository;
import tech.cwvermaak.weldforge.repository.ServiceAccountRepository;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/**
 * Which callers the app-authorization gate lets through without an
 * {@code x-app-authorization} header.
 *
 * <p>2026-09-11: SecurityConfig has always permitted the public order funnel
 * and the payment webhooks, but this gate still demanded an app-client key --
 * which neither a browser on www.weldforge.org nor a payment gateway can hold
 * -- so every self-serve order and every webhook got a 403 in production.
 */
class AppAuthorizationFilterExemptionTest {

    private final AppAuthorizationFilter filter = new AppAuthorizationFilter(
            mock(AppClientRepository.class), mock(ServiceAccountRepository.class));

    private boolean passes(String method, String path) throws Exception {
        MockHttpServletResponse res = new MockHttpServletResponse();
        FilterChain chain = mock(FilterChain.class);
        filter.doFilter(new MockHttpServletRequest(method, path), res, chain);
        boolean passed = mockingDetails(chain).getInvocations().stream()
                .anyMatch(i -> i.getMethod().getName().equals("doFilter"));
        if (!passed) assertThat(res.getStatus()).isEqualTo(403);
        return passed;
    }

    @ParameterizedTest(name = "{0} needs no app key")
    @ValueSource(strings = {
            "/api/public/orders",
            "/api/public/orders/abc/status",
            "/api/webhooks/stripe",
            "/api/webhooks/paddle",
            "/api/webhooks/payfast",
            "/api/webhooks/yoco",
    })
    void order_funnel_and_webhooks_pass(String path) throws Exception {
        assertThat(passes("POST", path)).isTrue();
    }

    @ParameterizedTest(name = "{0} still needs an app key")
    @ValueSource(strings = {
            "/api/public/anything-else",
            "/api/public/ordersx",
            "/api/webhooks-admin/things",
            "/api/webhooks",
            "/api/tenants",
            "/v3/api-docs",
    })
    void everything_else_still_gated(String path) throws Exception {
        assertThat(passes("POST", path)).isFalse();
    }

    @ParameterizedTest(name = "{0} keeps its existing exemption")
    @ValueSource(strings = {"/api/auth/login", "/api/admin/tenants", "/t/leap/oauth2/token", "/scim/v2/Users"})
    void existing_exemptions_unchanged(String path) throws Exception {
        assertThat(passes("POST", path)).isTrue();
    }

    @org.junit.jupiter.api.Test
    @DisplayName("an exempt path is exempt from this gate only -- the chain still runs")
    void exemption_continues_the_chain() throws Exception {
        FilterChain chain = mock(FilterChain.class);
        filter.doFilter(new MockHttpServletRequest("POST", "/api/public/orders"),
                new MockHttpServletResponse(), chain);
        verify(chain).doFilter(any(), any());
    }
}
