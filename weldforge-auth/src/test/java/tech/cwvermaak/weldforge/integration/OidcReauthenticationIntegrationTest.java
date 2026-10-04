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
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import tech.cwvermaak.weldforge.model.OidcClient;
import tech.cwvermaak.weldforge.model.Tenant;
import tech.cwvermaak.weldforge.repository.OidcClientRepository;
import tech.cwvermaak.weldforge.repository.TenantRepository;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

/**
 * {@code prompt=login} and {@code max_age} must re-authenticate the user.
 *
 * <p>Conformance defects D1 and D2. Before this:
 *
 * <ul>
 *   <li>{@code prompt=login} was <strong>ignored entirely</strong> — only
 *       {@code none} was ever compared. A relying party asking for a fresh
 *       authentication silently got the existing session, with a 200 and a
 *       code. A silent "no" to a security request is worse than a refusal.</li>
 *   <li>{@code max_age} was fed into the MFA step-up check, so a session that
 *       was seconds old could end a browser flow at {@code 400 mfa_required}
 *       if the user had no recently-used second factor. The spec asks when
 *       the USER last authenticated, and the required response is to
 *       re-authenticate, not to fail.</li>
 * </ul>
 *
 * <p>The OpenID Foundation suite tests both directly, which is why they were
 * the standing blockers on Basic OP certification.
 */
@SpringBootTest
@AutoConfigureMockMvc
@Testcontainers
@EnabledIfSystemProperty(named = "tests.integration", matches = "true")
@DisplayName("prompt=login and max_age re-authenticate")
class OidcReauthenticationIntegrationTest {

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
        registry.add("app.security.rate-limit.enabled", () -> "false");  // app.security.*, not app.* -- the wrong key silently does nothing
    }

    private static final String REDIRECT_URI = "https://rp.example.com/callback";
    private static final String PASSWORD = "correct horse battery staple";

    @Autowired MockMvc mvc;
    @Autowired TenantRepository tenants;
    @Autowired OidcClientRepository clients;

    private Tenant tenant;
    private String clientId;
    private Cookie session;

    @BeforeEach
    void seed() throws Exception {
        String tag = UUID.randomUUID().toString().substring(0, 8);
        tenant = tenants.saveAndFlush(Tenant.builder()
                .slug("reauth-" + tag).name("reauth-" + tag).displayName("reauth-" + tag).build());

        clientId = "rp-" + tag;
        clients.saveAndFlush(OidcClient.builder()
                .tenant(tenant)
                .clientId(clientId)
                .clientSecret("unused-" + tag)
                .name("Reauth test RP")
                .redirectUris(REDIRECT_URI)
                .scopes("openid profile email")
                .grantTypes("authorization_code")
                .requirePkce(false)
                .requireMfa(false)
                .maxAuthenticationAgeSeconds(0)
                .webOrigins("")
                .postLogoutRedirectUris("")
                .publicClient(false)
                .tokenEndpointAuthMethod("client_secret_basic")
                .build());

        String email = "reauth-" + tag + "@test.example";
        mvc.perform(post("/api/auth/register")
                .header("X-Tenant-Slug", tenant.getSlug())
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"name\":\"Reauth Tester\",\"email\":\"" + email
                         + "\",\"password\":\"" + PASSWORD + "\"}")).andReturn();

        MvcResult login = mvc.perform(post("/api/auth/login")
                .header("X-Tenant-Slug", tenant.getSlug())
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"identifier\":\"" + email + "\",\"password\":\"" + PASSWORD + "\"}"))
                .andReturn();
        session = login.getResponse().getCookie("wf_session");
        assertThat(session).as("login must set wf_session").isNotNull();
    }

    private MvcResult authorize(String... extraParams) throws Exception {
        var req = get("/t/" + tenant.getSlug() + "/oauth2/authorize")
                .cookie(session)
                .param("response_type", "code")
                .param("client_id", clientId)
                .param("redirect_uri", REDIRECT_URI)
                .param("scope", "openid")
                .param("state", "st-123");
        for (int i = 0; i + 1 < extraParams.length; i += 2) {
            req = req.param(extraParams[i], extraParams[i + 1]);
        }
        return mvc.perform(req).andReturn();
    }

    // ---- baseline ---------------------------------------------------------

    @Test
    @DisplayName("without prompt or max_age, a live session is used as it always was")
    void baseline_sessionIsUsed() throws Exception {
        MvcResult r = authorize();
        // Consent screen or straight to the redirect; either way NOT a bounce
        // back to the sign-in page.
        String location = r.getResponse().getHeader("Location");
        assertThat(r.getResponse().getStatus()).isIn(200, 302);
        if (location != null) {
            assertThat(location).doesNotContain("/login/");
        }
    }

    // ---- D2: prompt=login -------------------------------------------------

    @Test
    @DisplayName("prompt=login sends the user back through sign-in, despite a live session")
    void promptLogin_redirectsToLogin() throws Exception {
        MvcResult r = authorize("prompt", "login");

        assertThat(r.getResponse().getStatus()).isEqualTo(302);
        String location = r.getResponse().getHeader("Location");
        assertThat(location).contains("/login/");
        assertThat(location).contains("oidcReturnTo=");
    }

    @Test
    @DisplayName("select_account is honoured the same way, rather than refused")
    void promptSelectAccount_redirectsToLogin() throws Exception {
        MvcResult r = authorize("prompt", "select_account");

        assertThat(r.getResponse().getStatus()).isEqualTo(302);
        assertThat(r.getResponse().getHeader("Location")).contains("/login/");
    }

    @Test
    @DisplayName("coming back no fresher fails visibly instead of looping forever")
    void promptLogin_secondPass_doesNotLoop() throws Exception {
        // The marker says we already demanded a re-authentication for this
        // request. The session has not changed, so bouncing again would be an
        // infinite redirect -- far harder to diagnose than a protocol error.
        MvcResult r = authorize("prompt", "login",
                "wf_reauth_at", String.valueOf(java.time.Instant.now().getEpochSecond() + 5));

        assertThat(r.getResponse().getStatus()).isEqualTo(302);
        String location = r.getResponse().getHeader("Location");
        assertThat(location).startsWith(REDIRECT_URI);
        assertThat(location).contains("error=login_required");
        assertThat(location).contains("state=st-123");
    }

    @Test
    @DisplayName("prompt=login with prompt=none is a contradiction, not a silent winner")
    void promptLoginAndNone_isInvalidRequest() throws Exception {
        MvcResult r = authorize("prompt", "none login");

        assertThat(r.getResponse().getStatus()).isEqualTo(302);
        String location = r.getResponse().getHeader("Location");
        assertThat(location).startsWith(REDIRECT_URI);
        assertThat(location).contains("error=invalid_request");
    }

    // ---- D1: max_age ------------------------------------------------------

    @Test
    @DisplayName("a stale session under max_age re-authenticates, it does NOT 400")
    void maxAgeStale_redirectsToLogin() throws Exception {
        // max_age=0 cannot be satisfied by any existing session.
        MvcResult r = authorize("max_age", "0");

        assertThat(r.getResponse().getStatus()).isEqualTo(302);
        String location = r.getResponse().getHeader("Location");
        assertThat(location).contains("/login/");
        // The old behaviour: 400 mfa_required, in a browser, for a session
        // that had just been created.
        assertThat(r.getResponse().getStatus()).isNotEqualTo(400);
    }

    @Test
    @DisplayName("a session inside max_age is accepted without re-authenticating")
    void maxAgeFresh_proceeds() throws Exception {
        MvcResult r = authorize("max_age", "3600");

        String location = r.getResponse().getHeader("Location");
        if (location != null) {
            assertThat(location).doesNotContain("/login/");
        }
        assertThat(r.getResponse().getStatus()).isIn(200, 302);
    }

    @Test
    @DisplayName("max_age with prompt=none cannot interact, so it says login_required")
    void maxAgeStaleWithPromptNone_isLoginRequired() throws Exception {
        MvcResult r = authorize("max_age", "0", "prompt", "none");

        assertThat(r.getResponse().getStatus()).isEqualTo(302);
        String location = r.getResponse().getHeader("Location");
        assertThat(location).startsWith(REDIRECT_URI);
        assertThat(location).contains("error=login_required");
    }
}
