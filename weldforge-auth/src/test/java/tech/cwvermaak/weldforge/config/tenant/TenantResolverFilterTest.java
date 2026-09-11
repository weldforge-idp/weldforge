package tech.cwvermaak.weldforge.config.tenant;

import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Resolution order from {@link TenantResolverFilter}: header → path → host →
 * default fallback. See {@code docs/auth-url-spec.md}.
 */
class TenantResolverFilterTest {

    private final PublicHostProperties publicHost = publicHost();
    private final TenantResolverFilter filter = new TenantResolverFilter(publicHost);

    @AfterEach
    void clear() {
        TenantContext.clear();
    }

    @Test
    @DisplayName("X-Tenant-Slug header wins over everything")
    void headerWins() throws Exception {
        HttpServletRequest req = request("/t/path-slug/anything", "host-slug.sso.weldforge.org");
        when(req.getHeader(TenantResolverFilter.HEADER)).thenReturn("HeaderSlug");

        AtomicReference<String> seen = new AtomicReference<>();
        FilterChain chain = (r, s) -> seen.set(TenantContext.get());

        filter.doFilter(req, mock(HttpServletResponse.class), chain);

        assertThat(seen.get()).isEqualTo("headerslug");
    }

    @Test
    @DisplayName("/t/{slug}/ path prefix beats host subdomain")
    void pathBeatsHost() throws Exception {
        HttpServletRequest req = request("/t/path-slug/oauth2/authorize",
                "host-slug.sso.weldforge.org");

        AtomicReference<String> seen = new AtomicReference<>();
        filter.doFilter(req, mock(HttpServletResponse.class),
                (r, s) -> seen.set(TenantContext.get()));

        assertThat(seen.get()).isEqualTo("path-slug");
    }

    @Test
    @DisplayName("Host subdomain resolves when no header / no path prefix")
    void hostSubdomain() throws Exception {
        HttpServletRequest req = request("/login", "acme.sso.weldforge.org");

        AtomicReference<String> seen = new AtomicReference<>();
        filter.doFilter(req, mock(HttpServletResponse.class),
                (r, s) -> seen.set(TenantContext.get()));

        assertThat(seen.get()).isEqualTo("acme");
    }

    @Test
    @DisplayName("Apex host falls back to default — never resolves to a tenant")
    void apexFallsBack() throws Exception {
        HttpServletRequest req = request("/api/admin/tenants", "sso.weldforge.org");

        AtomicReference<String> seen = new AtomicReference<>();
        filter.doFilter(req, mock(HttpServletResponse.class),
                (r, s) -> seen.set(TenantContext.get()));

        assertThat(seen.get()).isEqualTo(TenantResolverFilter.DEFAULT_TENANT);
    }

    @Test
    @DisplayName("Reserved root labels (www, api, admin, ...) never resolve to a tenant")
    void reservedLabelsRejected() throws Exception {
        for (String reserved : List.of("www", "api", "admin", "app", "mail", "static")) {
            HttpServletRequest req = request("/anything",
                    reserved + ".sso.weldforge.org");

            AtomicReference<String> seen = new AtomicReference<>();
            filter.doFilter(req, mock(HttpServletResponse.class),
                    (r, s) -> seen.set(TenantContext.get()));

            assertThat(seen.get())
                    .as("reserved label %s should fall through to default", reserved)
                    .isEqualTo(TenantResolverFilter.DEFAULT_TENANT);
        }
    }

    @Test
    @DisplayName("Multi-label subdomains do not resolve (only single-label slugs)")
    void multiLabelRejected() throws Exception {
        HttpServletRequest req = request("/login",
                "deploys.acme.sso.weldforge.org");

        AtomicReference<String> seen = new AtomicReference<>();
        filter.doFilter(req, mock(HttpServletResponse.class),
                (r, s) -> seen.set(TenantContext.get()));

        assertThat(seen.get()).isEqualTo(TenantResolverFilter.DEFAULT_TENANT);
    }

    @Test
    @DisplayName("Hosts outside the configured base domain do not resolve")
    void foreignHostRejected() throws Exception {
        HttpServletRequest req = request("/login", "acme.example.com");

        AtomicReference<String> seen = new AtomicReference<>();
        filter.doFilter(req, mock(HttpServletResponse.class),
                (r, s) -> seen.set(TenantContext.get()));

        assertThat(seen.get()).isEqualTo(TenantResolverFilter.DEFAULT_TENANT);
    }

    @Test
    @DisplayName("?tenant= query parameter is ignored (legacy form removed)")
    void queryParamIgnored() throws Exception {
        HttpServletRequest req = request("/login", "sso.weldforge.org");
        when(req.getParameter("tenant")).thenReturn("acme");

        AtomicReference<String> seen = new AtomicReference<>();
        filter.doFilter(req, mock(HttpServletResponse.class),
                (r, s) -> seen.set(TenantContext.get()));

        assertThat(seen.get())
                .as("the legacy ?tenant= form must no longer resolve tenants")
                .isEqualTo(TenantResolverFilter.DEFAULT_TENANT);
    }

    @Test
    @DisplayName("Host header port suffix is stripped before matching")
    void portStripped() throws Exception {
        HttpServletRequest req = request("/login", "acme.sso.weldforge.org");
        // getServerName() should not include the port — sanity check.
        AtomicReference<String> seen = new AtomicReference<>();
        filter.doFilter(req, mock(HttpServletResponse.class),
                (r, s) -> seen.set(TenantContext.get()));
        assertThat(seen.get()).isEqualTo("acme");

        // PublicHostProperties also strips a port directly (defensive — in
        // case the host is read from a Host: header rather than getServerName).
        assertThat(publicHost.slugFromHost("acme.sso.weldforge.org:8443"))
                .isEqualTo("acme");
    }

    @Test
    @DisplayName("originForTenant builds scheme + per-tenant subdomain")
    void originBuilder() {
        assertThat(publicHost.originForTenant("acme"))
                .isEqualTo("https://acme.sso.weldforge.org");
        assertThat(publicHost.originForTenant(null))
                .isEqualTo("https://sso.weldforge.org");
    }

    // ── B-TEN-7: the request's own tenant survives the JWT filter ──────────

    @Test
    @DisplayName("the resolver records its pick on the request, and it outlives a JWT's context change")
    void requestedTenantRecorded() throws Exception {
        org.springframework.mock.web.MockHttpServletRequest req =
                new org.springframework.mock.web.MockHttpServletRequest("POST", "/api/auth/refresh");
        req.setServerName("sso.weldforge.org");
        req.addHeader(TenantResolverFilter.HEADER, "Default");

        AtomicReference<String> requested = new AtomicReference<>();
        filter.doFilter(req, mock(HttpServletResponse.class), (r, s) -> {
            // What JwtAuthenticationFilter does with a session cookie's JWT.
            TenantContext.set("intellisuite", 6L, null);
            requested.set(TenantResolverFilter.requestedTenant((HttpServletRequest) r));
        });

        assertThat(requested.get()).isEqualTo("default");
    }

    @Test
    @DisplayName("requestedTenantOrContext reads the current request, else falls back to the context")
    void requestedTenantOrContext() {
        org.springframework.mock.web.MockHttpServletRequest req =
                new org.springframework.mock.web.MockHttpServletRequest("POST", "/api/auth/forgot-password");
        req.setAttribute(TenantResolverFilter.REQUESTED_TENANT_ATTRIBUTE, "leap");
        TenantContext.set("intellisuite");
        try {
            org.springframework.web.context.request.RequestContextHolder.setRequestAttributes(
                    new org.springframework.web.context.request.ServletRequestAttributes(req));
            assertThat(TenantResolverFilter.requestedTenantOrContext()).isEqualTo("leap");
        } finally {
            org.springframework.web.context.request.RequestContextHolder.resetRequestAttributes();
        }
        assertThat(TenantResolverFilter.requestedTenantOrContext()).isEqualTo("intellisuite");
    }

    // ── helpers ──────────────────────────────────────────────────────

    private static PublicHostProperties publicHost() {
        PublicHostProperties p = new PublicHostProperties();
        p.setBaseDomain("sso.weldforge.org");
        p.setScheme("https");
        p.setReservedLabels(List.of("www", "api", "admin", "app", "mail", "static"));
        return p;
    }

    private static HttpServletRequest request(String requestUri, String host) {
        HttpServletRequest req = mock(HttpServletRequest.class);
        when(req.getRequestURI()).thenReturn(requestUri);
        when(req.getServerName()).thenReturn(host);
        return req;
    }
}
