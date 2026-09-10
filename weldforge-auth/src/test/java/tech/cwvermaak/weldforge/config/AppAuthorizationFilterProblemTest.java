package tech.cwvermaak.weldforge.config;

import jakarta.servlet.FilterChain;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import tech.cwvermaak.weldforge.repository.AppClientRepository;
import tech.cwvermaak.weldforge.repository.ServiceAccountRepository;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/**
 * CONF-7.3: the app-authorization gate's refusals are 403 problem documents.
 * They used to be a bare text body, the one /api/** error a JSON client could
 * not parse at all.
 */
class AppAuthorizationFilterProblemTest {

    private final AppClientRepository appClients = mock(AppClientRepository.class);
    private final ServiceAccountRepository serviceAccounts = mock(ServiceAccountRepository.class);
    private final AppAuthorizationFilter filter = new AppAuthorizationFilter(appClients, serviceAccounts);

    private MockHttpServletResponse run(MockHttpServletRequest req) throws Exception {
        MockHttpServletResponse res = new MockHttpServletResponse();
        FilterChain chain = mock(FilterChain.class);
        filter.doFilter(req, res, chain);
        verify(chain, never()).doFilter(any(), any());
        return res;
    }

    @Test
    @DisplayName("A missing x-app-authorization header is a 403 problem")
    void missing_header() throws Exception {
        MockHttpServletResponse res = run(new MockHttpServletRequest("GET", "/api/webhooks-admin/things"));

        assertThat(res.getStatus()).isEqualTo(403);
        assertThat(res.getContentType()).startsWith("application/problem+json");
        assertThat(res.getContentAsString())
                .contains("\"type\":\"tag:weldforge.org,2026:problem:forbidden\"")
                .contains("\"status\":403")
                .contains("\"detail\":\"Missing or invalid x-app-authorization header\"");
    }

    @Test
    @DisplayName("An unknown service-account token is a 403 problem naming the reason")
    void unknown_service_account() throws Exception {
        when(serviceAccounts.findByTokenHashAndEnabledTrue(any())).thenReturn(Optional.empty());
        MockHttpServletRequest req = new MockHttpServletRequest("GET", "/api/webhooks-admin/things");
        req.addHeader("x-app-authorization", "wf_svc_not-a-real-token");

        MockHttpServletResponse res = run(req);

        assertThat(res.getStatus()).isEqualTo(403);
        assertThat(res.getContentAsString()).contains("\"detail\":\"Invalid service account token\"");
    }

    @Test
    @DisplayName("An unknown app-client key is a 403 problem")
    void unknown_app_client() throws Exception {
        when(appClients.findByApiKeyHashAndEnabledTrue(any())).thenReturn(Optional.empty());
        MockHttpServletRequest req = new MockHttpServletRequest("GET", "/api/webhooks-admin/things");
        req.addHeader("x-app-authorization", "wf_live_not-a-real-key");

        MockHttpServletResponse res = run(req);

        assertThat(res.getStatus()).isEqualTo(403);
        assertThat(res.getContentType()).startsWith("application/problem+json");
    }
}
