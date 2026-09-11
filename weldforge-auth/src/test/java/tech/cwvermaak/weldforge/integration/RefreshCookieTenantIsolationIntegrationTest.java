package tech.cwvermaak.weldforge.integration;

import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import tech.cwvermaak.weldforge.model.AuthProvider;
import tech.cwvermaak.weldforge.model.Tenant;
import tech.cwvermaak.weldforge.model.User;
import tech.cwvermaak.weldforge.repository.AuditEventRepository;
import tech.cwvermaak.weldforge.repository.TenantRepository;
import tech.cwvermaak.weldforge.repository.UserRepository;
import tech.cwvermaak.weldforge.service.AuthService;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

/**
 * B-TEN-7, through the real filter chain and real cookies: one browser signed
 * in to two tenants keeps two independent sessions, and a refresh is only ever
 * answered with the requested tenant's session.
 *
 * <p>2026-09-11: the refresh cookie had one name for every tenant under the
 * base domain. An {@code intellisuite} sign-in overwrote the operator's
 * {@code default} cookie, and the admin portal's next refresh came back as the
 * {@code intellisuite} user.
 */
@SpringBootTest
@AutoConfigureMockMvc
@Testcontainers
@EnabledIfSystemProperty(named = "tests.integration", matches = "true")
@DisplayName("Refresh cookies: one session per tenant, refresh bound to its tenant")
class RefreshCookieTenantIsolationIntegrationTest {

    @Container
    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:16-alpine")
            .withDatabaseName("weldforge_test")
            .withUsername("test")
            .withPassword("test");

    @DynamicPropertySource
    static void datasource(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url",      POSTGRES::getJdbcUrl);
        registry.add("spring.datasource.username", POSTGRES::getUsername);
        registry.add("spring.datasource.password", POSTGRES::getPassword);
        registry.add("app.crypto.secret", () -> "ci-only-crypto-secret-0123456789abcdef");
        registry.add("spring.jpa.hibernate.ddl-auto", () -> "validate");
        registry.add("app.security.password.breach-check.enabled", () -> "false");
        registry.add("app.security.rate-limit.enabled", () -> "false");
    }

    private static final String PASSWORD = "correct horse battery staple";

    @Autowired MockMvc mvc;
    @Autowired TenantRepository tenants;
    @Autowired UserRepository users;
    @Autowired PasswordEncoder passwordEncoder;
    @Autowired AuditEventRepository auditEvents;

    private Tenant home;
    private Tenant other;
    private User alice;   // in `default`
    private User bob;     // in the other tenant

    @BeforeEach
    void twoTenantsTwoUsers() {
        home = tenants.findBySlug("default").orElseThrow();
        String tag = UUID.randomUUID().toString().substring(0, 8);
        other = tenants.save(Tenant.builder().slug("suite-" + tag).name("Suite " + tag)
                .displayName("Suite " + tag).build());
        alice = user(home, "alice-" + tag);
        bob = user(other, "bob-" + tag);
    }

    private User user(Tenant t, String name) {
        return users.save(User.builder()
                .tenant(t).username(name).email(name + "@test.example")
                .password(passwordEncoder.encode(PASSWORD))
                .provider(AuthProvider.LOCAL).providerId(name).active(true)
                .build());
    }

    // ---- a tiny browser -------------------------------------------------------

    /** Cookies by name, like a browser's jar for the base domain. */
    private final Map<String, String> jar = new LinkedHashMap<>();

    private MvcResult send(MockHttpServletRequestBuilder req) throws Exception {
        if (!jar.isEmpty()) {
            req.cookie(jar.entrySet().stream()
                    .map(e -> new Cookie(e.getKey(), e.getValue())).toArray(Cookie[]::new));
        }
        MvcResult r = mvc.perform(req).andReturn();
        for (Cookie c : r.getResponse().getCookies()) {
            if (c.getMaxAge() == 0) jar.remove(c.getName());
            else jar.put(c.getName(), c.getValue());
        }
        return r;
    }

    private MvcResult login(Tenant t, User u) throws Exception {
        MvcResult r = send(post("/api/auth/login").header("X-Tenant-Slug", t.getSlug())
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"identifier\":\"" + u.getEmail() + "\",\"password\":\"" + PASSWORD + "\"}"));
        assertThat(r.getResponse().getStatus()).as("login %s", u.getEmail()).isEqualTo(200);
        return r;
    }

    private MvcResult refresh(String tenantSlug) throws Exception {
        return send(post("/api/auth/refresh").header("X-Tenant-Slug", tenantSlug));
    }

    /** The `tenant` and `sub`/email claims of the access token in a response body. */
    private static Map<String, Object> claims(MvcResult r) throws Exception {
        String body = r.getResponse().getContentAsString();
        String token = body.replaceAll(".*\"token\":\"([^\"]+)\".*", "$1");
        String payload = new String(Base64.getUrlDecoder().decode(token.split("\\.")[1]), StandardCharsets.UTF_8);
        return new com.fasterxml.jackson.databind.ObjectMapper().readValue(payload, Map.class);
    }

    private static List<String> setCookieNames(MvcResult r) {
        return Arrays.stream(r.getResponse().getCookies()).map(Cookie::getName).toList();
    }

    // ---- browsers --------------------------------------------------------------

    @Test
    @DisplayName("sign-in sets the tenant's own refresh cookie and the legacy one")
    void login_sets_both_cookies() throws Exception {
        MvcResult r = login(home, alice);

        assertThat(setCookieNames(r)).contains(AuthService.refreshCookieName("default"), AuthService.REFRESH_COOKIE);
        Cookie own = r.getResponse().getCookie(AuthService.refreshCookieName("default"));
        assertThat(own.isHttpOnly()).isTrue();
        assertThat(own.getPath()).isEqualTo("/api/auth");
    }

    @Test
    @DisplayName("the incident: signed in to two tenants, each refresh returns its own tenant's session")
    void two_tenants_one_browser() throws Exception {
        login(home, alice);
        login(other, bob);     // the legacy cookie now holds bob's session

        MvcResult homeRefresh = refresh("default");
        assertThat(homeRefresh.getResponse().getStatus()).isEqualTo(200);
        assertThat(claims(homeRefresh).get("tenant")).isEqualTo("default");
        assertThat(claims(homeRefresh).get("sub").toString()).isEqualTo(alice.getEmail());

        MvcResult otherRefresh = refresh(other.getSlug());
        assertThat(otherRefresh.getResponse().getStatus()).isEqualTo(200);
        assertThat(claims(otherRefresh).get("tenant")).isEqualTo(other.getSlug());
        assertThat(claims(otherRefresh).get("sub").toString()).isEqualTo(bob.getEmail());

        // And again: neither rotation disturbed the other.
        assertThat(refresh("default").getResponse().getStatus()).isEqualTo(200);
        assertThat(refresh(other.getSlug()).getResponse().getStatus()).isEqualTo(200);
    }

    @Test
    @DisplayName("a browser refresh does not rewrite the legacy cookie")
    void per_tenant_refresh_leaves_legacy_alone() throws Exception {
        login(home, alice);

        MvcResult r = refresh("default");

        assertThat(setCookieNames(r)).contains(AuthService.refreshCookieName("default"))
                .doesNotContain(AuthService.REFRESH_COOKIE);
    }

    @Test
    @DisplayName("a tenant the browser has no session for gets 401, never another tenant's session")
    void no_session_for_that_tenant() throws Exception {
        login(other, bob);   // only the other tenant: its own cookie + the legacy one

        MvcResult r = refresh("default");

        assertThat(r.getResponse().getStatus()).isEqualTo(401);
        assertThat(r.getResponse().getContentAsString()).doesNotContain("\"token\"");
        // Bob's session was not consumed by the refused attempt.
        assertThat(refresh(other.getSlug()).getResponse().getStatus()).isEqualTo(200);
    }

    // ---- server-side proxies (Safe Space): legacy cookie only -------------------

    private MvcResult legacyRefresh(String tenantSlug, String rawToken) throws Exception {
        return mvc.perform(post("/api/auth/refresh").header("X-Tenant-Slug", tenantSlug)
                        .cookie(new Cookie(AuthService.REFRESH_COOKIE, rawToken)))
                .andReturn();
    }

    @Test
    @DisplayName("a proxy sending only `refresh_token` keeps working, and gets `refresh_token` back")
    void legacy_proxy_still_works() throws Exception {
        String raw = login(other, bob).getResponse().getCookie(AuthService.REFRESH_COOKIE).getValue();

        MvcResult r = legacyRefresh(other.getSlug(), raw);

        assertThat(r.getResponse().getStatus()).isEqualTo(200);
        assertThat(claims(r).get("tenant")).isEqualTo(other.getSlug());
        Cookie rotated = r.getResponse().getCookie(AuthService.REFRESH_COOKIE);
        assertThat(rotated).isNotNull();
        assertThat(rotated.getValue()).isNotBlank().isNotEqualTo(raw);
        // The rotated legacy token works on the next refresh, as a proxy would use it.
        assertThat(legacyRefresh(other.getSlug(), rotated.getValue()).getResponse().getStatus()).isEqualTo(200);
    }

    @Test
    @DisplayName("a legacy cookie from another tenant is refused, audited, and left intact")
    void legacy_cookie_from_another_tenant() throws Exception {
        String raw = login(other, bob).getResponse().getCookie(AuthService.REFRESH_COOKIE).getValue();
        long before = auditEvents.count();

        MvcResult r = legacyRefresh("default", raw);

        assertThat(r.getResponse().getStatus()).isEqualTo(401);
        assertThat(r.getResponse().getContentType()).startsWith("application/problem+json");
        assertThat(auditEvents.findAll()).anyMatch(e ->
                "auth.refresh.tenant_mismatch".equals(e.getEventType())
                        && e.getTargetId() != null);
        assertThat(auditEvents.count()).isGreaterThan(before);
        // Not consumed: bob's own tenant can still use exactly that token.
        assertThat(legacyRefresh(other.getSlug(), raw).getResponse().getStatus()).isEqualTo(200);
    }

    // ---- a leftover session cookie never picks the tenant of a sign-in ---------

    @Test
    @DisplayName("signing in to a second tenant is not redirected by the first tenant's session cookie")
    void login_not_redirected_by_session_cookie() throws Exception {
        login(home, alice);                 // the jar now holds alice's wf_session
        MvcResult r = login(other, bob);    // must authenticate bob in HIS tenant

        assertThat(claims(r).get("tenant")).isEqualTo(other.getSlug());
        assertThat(claims(r).get("sub").toString()).isEqualTo(bob.getEmail());
    }

    @Test
    @DisplayName("a registration lands in the tenant it names, whatever session cookie is lying around")
    void register_not_redirected_by_session_cookie() throws Exception {
        login(other, bob);                  // bob's wf_session (other tenant) in the jar
        String tag = UUID.randomUUID().toString().substring(0, 8);

        MvcResult r = send(post("/api/auth/register").header("X-Tenant-Slug", "default")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"name\":\"carol-" + tag + "\",\"email\":\"carol-" + tag
                        + "@test.example\",\"password\":\"" + PASSWORD + "\"}"));

        assertThat(r.getResponse().getStatus()).isEqualTo(200);
        assertThat(users.findByTenantIdAndEmailIgnoreCase(home.getId(), "carol-" + tag + "@test.example"))
                .isPresent();
        assertThat(users.findByTenantIdAndEmailIgnoreCase(other.getId(), "carol-" + tag + "@test.example"))
                .isEmpty();
    }
}
