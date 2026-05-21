package tech.cwvermaak.weldforge.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.util.ReflectionTestUtils;
import tech.cwvermaak.weldforge.config.tenant.PublicHostProperties;
import tech.cwvermaak.weldforge.config.tenant.TenantContext;
import tech.cwvermaak.weldforge.config.tenant.TenantResolverFilter;
import tech.cwvermaak.weldforge.model.Tenant;
import tech.cwvermaak.weldforge.model.User;
import tech.cwvermaak.weldforge.repository.TenantRepository;
import tech.cwvermaak.weldforge.repository.UserRepository;
import tech.cwvermaak.weldforge.service.JwtService;

import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Cross-tenant cookie safety — see {@code docs/auth-url-spec.md} §"Cookies".
 * The session cookie is base-domain-scoped, so the browser sends an
 * {@code acme} session to {@code contoso.sso.weldforge.org}. The filter
 * must refuse to authenticate it.
 */
class JwtAuthenticationFilterTest {

    private static final String SECRET =
            "test-secret-0123456789abcdef0123456789abcdef0123456789abcdef0123";

    private final PublicHostProperties publicHost = publicHost();
    private final TenantResolverFilter tenantResolver = new TenantResolverFilter(publicHost);

    private final JwtService jwtService = jwtService();
    private final UserRepository userRepository = mock(UserRepository.class);
    private final TenantRepository tenantRepository = mock(TenantRepository.class);

    private final JwtAuthenticationFilter filter =
            new JwtAuthenticationFilter(jwtService, userRepository, tenantRepository, tenantResolver);

    @BeforeEach
    void wireUser() {
        User u = User.builder().id(7L).email("u@acme.test")
                .tokenVersion(0)
                .tenant(Tenant.builder().id(1L).slug("acme").build())
                .build();
        when(userRepository.findByTenant_SlugAndEmailIgnoreCase("acme", "u@acme.test"))
                .thenReturn(Optional.of(u));
    }

    @AfterEach
    void clear() {
        SecurityContextHolder.clearContext();
        TenantContext.clear();
    }

    @Test
    @DisplayName("JWT tenant matches host subdomain — request authenticated")
    void match_authenticates() throws Exception {
        HttpServletRequest req = req("acme.sso.weldforge.org", "/api/some/path");
        when(req.getHeader("Authorization"))
                .thenReturn("Bearer " + token("u@acme.test", "acme", 1L, false));

        AtomicBoolean chained = new AtomicBoolean(false);
        AtomicReference<String> seenTenant = new AtomicReference<>();
        FilterChain chain = (r, s) -> {
            chained.set(true);
            seenTenant.set(TenantContext.get());
        };

        filter.doFilter(req, mock(HttpServletResponse.class), chain);

        assertThat(chained).isTrue();
        assertThat(seenTenant.get()).isEqualTo("acme");
        assertThat(SecurityContextHolder.getContext().getAuthentication())
                .as("authenticated when JWT tenant matches host")
                .isNotNull();
    }

    @Test
    @DisplayName("JWT tenant mismatches host subdomain — request runs anonymous")
    void mismatch_refuses_authentication() throws Exception {
        HttpServletRequest req = req("contoso.sso.weldforge.org", "/api/some/path");
        when(req.getHeader("Authorization"))
                .thenReturn("Bearer " + token("u@acme.test", "acme", 1L, false));

        FilterChain chain = (r, s) -> { /* observed via SecurityContextHolder */ };
        filter.doFilter(req, mock(HttpServletResponse.class), chain);

        assertThat(SecurityContextHolder.getContext().getAuthentication())
                .as("a tenant=acme JWT must not authenticate against tenant=contoso's subdomain")
                .isNull();
    }

    @Test
    @DisplayName("Super-admin can cross tenant boundaries by design (picker UX)")
    void super_admin_crosses_tenants() throws Exception {
        HttpServletRequest req = req("contoso.sso.weldforge.org", "/api/admin/users");
        // Super-admin's home tenant is "acme" but they navigate to contoso.
        when(req.getHeader("Authorization"))
                .thenReturn("Bearer " + token("super@acme.test", "acme", 1L, true));

        FilterChain chain = (r, s) -> {};
        filter.doFilter(req, mock(HttpServletResponse.class), chain);

        assertThat(SecurityContextHolder.getContext().getAuthentication())
                .as("super-admin JWT may cross subdomains via the picker")
                .isNotNull();
    }

    @Test
    @DisplayName("Apex host (no implicit tenant) does not enforce binding")
    void apex_host_allows_any_tenant_jwt() throws Exception {
        HttpServletRequest req = req("sso.weldforge.org", "/api/admin/tenants");
        when(req.getHeader("Authorization"))
                .thenReturn("Bearer " + token("u@acme.test", "acme", 1L, false));

        FilterChain chain = (r, s) -> {};
        filter.doFilter(req, mock(HttpServletResponse.class), chain);

        assertThat(SecurityContextHolder.getContext().getAuthentication())
                .as("apex falls back to JWT-as-authoritative for admin-portal use")
                .isNotNull();
    }

    @Test
    @DisplayName("JWT tenant mismatches /t/{slug}/ path — request runs anonymous")
    void path_prefix_mismatch_refuses_authentication() throws Exception {
        // RP redirected user to /t/contoso/oauth2/authorize but their JWT is for acme.
        // The user must NOT be considered logged in for the purposes of issuing
        // a code for an RP registered in contoso.
        HttpServletRequest req = req("sso.weldforge.org", "/t/contoso/oauth2/authorize");
        when(req.getHeader("Authorization"))
                .thenReturn("Bearer " + token("u@acme.test", "acme", 1L, false));

        FilterChain chain = (r, s) -> {};
        filter.doFilter(req, mock(HttpServletResponse.class), chain);

        assertThat(SecurityContextHolder.getContext().getAuthentication())
                .as("tenant=acme JWT must not authenticate against /t/contoso/oauth2/...")
                .isNull();
    }

    // ── helpers ──────────────────────────────────────────────────────

    private static PublicHostProperties publicHost() {
        PublicHostProperties p = new PublicHostProperties();
        p.setBaseDomain("sso.weldforge.org");
        p.setScheme("https");
        p.setReservedLabels(List.of("www", "api", "admin"));
        return p;
    }

    private static JwtService jwtService() {
        JwtService s = new JwtService();
        ReflectionTestUtils.setField(s, "secret", SECRET);
        ReflectionTestUtils.setField(s, "accessExpirationMs", 300_000L);
        ReflectionTestUtils.setField(s, "refreshExpirationMs", 604_800_000L);
        return s;
    }

    private String token(String email, String slug, Long tid, boolean sa) {
        return jwtService.generateAccessToken(email, tid, slug, sa, 0,
                null, null, sa ? "SUPER_ADMIN" : "NONE",
                "https://sso.weldforge.org/t/" + slug);
    }

    private static HttpServletRequest req(String host, String path) {
        HttpServletRequest r = mock(HttpServletRequest.class);
        when(r.getServerName()).thenReturn(host);
        when(r.getRequestURI()).thenReturn(path);
        return r;
    }
}
