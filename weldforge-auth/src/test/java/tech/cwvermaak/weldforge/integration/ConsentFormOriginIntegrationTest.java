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
import tech.cwvermaak.weldforge.service.JwtService;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

/**
 * The OIDC consent form must be submittable by a real browser.
 *
 * <p>From 2026-09-10 until 2026-09-21 it was not, in production. Every response
 * carried {@code Referrer-Policy: no-referrer}. Under the Fetch spec, a non-GET
 * request from a no-referrer document serialises its {@code Origin} header as
 * {@code "null"} — <em>even when it is same-origin</em>. Spring's CORS processor
 * treats {@code Origin: null} as cross-origin and refuses it, so clicking
 * <em>Allow</em> on the consent screen answered {@code 403 Invalid CORS
 * request} and the controller never ran. No new user and no new client could
 * complete a first sign-in.
 *
 * <p>Nothing caught it because nothing here sends an {@code Origin} header:
 * curl does not, and no existing test drove {@code /authorize/decide} through
 * the filter chain at all. V54's standing consent grants then hid it from every
 * existing user. It was found by the intelli-accounting session on 2026-09-21.
 *
 * <p>These tests pin both halves of the contract:
 * <ol>
 *   <li>the page that renders the form sends a policy under which a browser
 *       posts a <em>real</em> Origin ({@code same-origin}); and</li>
 *   <li>a POST carrying that real, same-origin Origin completes the flow —
 *       302 to the redirect URI with a code and the state.</li>
 * </ol>
 * They deliberately do <strong>not</strong> make {@code Origin: null} succeed.
 * {@code null} is also what sandboxed iframes, {@code data:} and
 * {@code file:} documents send; trusting it with credentials would be the
 * wrong fix. The browser is made to stop sending it instead.
 */
@SpringBootTest
@AutoConfigureMockMvc
@Testcontainers
@EnabledIfSystemProperty(named = "tests.integration", matches = "true")
@DisplayName("The consent form can be submitted by a real browser")
class ConsentFormOriginIntegrationTest {

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
        registry.add("app.rate-limit.enabled", () -> "false");
    }

    /** MockMvc's default request origin: scheme http, host localhost, port 80. */
    private static final String SAME_ORIGIN = "http://localhost";
    private static final String REDIRECT_URI = "https://rp.example.com/callback";
    private static final String PASSWORD = "correct horse battery staple";

    @Autowired MockMvc mvc;
    @Autowired TenantRepository tenants;
    @Autowired OidcClientRepository clients;
    @Autowired JwtService jwtService;

    private Tenant tenant;
    private String clientId;
    private String email;
    private Cookie session;

    @BeforeEach
    void seed() throws Exception {
        String tag = UUID.randomUUID().toString().substring(0, 8);
        tenant = tenants.saveAndFlush(Tenant.builder()
                .slug("consent-" + tag).name("consent-" + tag).displayName("consent-" + tag).build());

        clientId = "rp-" + tag;
        clients.saveAndFlush(OidcClient.builder()
                .tenant(tenant)
                .clientId(clientId)
                .clientSecret("unused-in-this-test-" + tag)
                .name("Consent test RP")
                .redirectUris(REDIRECT_URI)
                .scopes("openid profile email")
                .grantTypes("authorization_code")
                // No PKCE: the form then replays an EMPTY code_challenge, which
                // exercises the blankToNull fix from 2026-09-20 on the same path.
                .requirePkce(false)
                .requireMfa(false)
                .maxAuthenticationAgeSeconds(0)
                .webOrigins("")
                .postLogoutRedirectUris("")
                .publicClient(false)
                .tokenEndpointAuthMethod("client_secret_basic")
                .build());

        email = "consent-" + tag + "@test.example";
        mvc.perform(post("/api/auth/register")
                        .header("X-Tenant-Slug", tenant.getSlug())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"name\":\"Consent Tester\",\"email\":\"" + email
                                 + "\",\"password\":\"" + PASSWORD + "\"}"))
                .andReturn();

        MvcResult login = mvc.perform(post("/api/auth/login")
                        .header("X-Tenant-Slug", tenant.getSlug())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"identifier\":\"" + email + "\",\"password\":\"" + PASSWORD + "\"}"))
                .andReturn();
        session = login.getResponse().getCookie("wf_session");
        assertThat(session)
                .as("login must set the wf_session cookie the /authorize flow runs on")
                .isNotNull();
    }

    private MvcResult decide(String origin, String decision) throws Exception {
        String csrf = jwtService.generateConsentCsrfToken(email, tenant.getId(), tenant.getSlug());
        var req = post("/t/" + tenant.getSlug() + "/oauth2/authorize/decide")
                .cookie(session)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .param("client_id", clientId)
                .param("redirect_uri", REDIRECT_URI)
                .param("scope", "openid")
                .param("state", "st-123")
                .param("nonce", "n-456")
                // Exactly what the rendered form posts when the request had no PKCE.
                .param("code_challenge", "")
                .param("code_challenge_method", "")
                .param("max_age", "")
                .param("csrf_token", csrf)
                .param("decision", decision);
        if (origin != null) req = req.header("Origin", origin);
        return mvc.perform(req).andReturn();
    }

    @Test
    @DisplayName("the consent page sends a Referrer-Policy under which browsers post a real Origin")
    void consent_page_referrer_policy_keeps_the_origin() throws Exception {
        MvcResult page = mvc.perform(get("/t/" + tenant.getSlug() + "/oauth2/authorize")
                        .cookie(session)
                        .param("response_type", "code")
                        .param("client_id", clientId)
                        .param("redirect_uri", REDIRECT_URI)
                        .param("scope", "openid")
                        .param("state", "st-123"))
                .andReturn();

        assertThat(page.getResponse().getContentAsString())
                .as("precondition: a first authorization renders the consent form")
                .contains("/oauth2/authorize/decide");

        assertThat(page.getResponse().getHeader("Referrer-Policy"))
                .as("no-referrer makes the browser send 'Origin: null' on the same-origin "
                  + "form POST, which CORS refuses. same-origin still withholds Referer "
                  + "from third parties, which was the point of the header.")
                .isEqualTo("same-origin");
    }

    @Test
    @DisplayName("Allow with a same-origin Origin completes: 302 to redirect_uri with code and state")
    void allow_with_same_origin_origin_completes() throws Exception {
        MvcResult r = decide(SAME_ORIGIN, "allow");

        assertThat(r.getResponse().getStatus())
                .as("was 403 'Invalid CORS request' when browsers sent Origin: null; body: %s",
                    r.getResponse().getContentAsString())
                .isEqualTo(302);
        String location = r.getResponse().getHeader("Location");
        assertThat(location).startsWith(REDIRECT_URI + "?");
        assertThat(location).contains("code=");
        assertThat(location).contains("state=st-123");
    }

    @Test
    @DisplayName("Deny still redirects with error=access_denied")
    void deny_still_redirects_with_access_denied() throws Exception {
        MvcResult r = decide(SAME_ORIGIN, "deny");

        assertThat(r.getResponse().getStatus()).isEqualTo(302);
        String location = r.getResponse().getHeader("Location");
        assertThat(location).startsWith(REDIRECT_URI + "?");
        assertThat(location).contains("error=access_denied");
        assertThat(location).doesNotContain("code=");
    }

    @Test
    @DisplayName("Origin: null is still refused — the fix is to stop browsers sending it, not to trust it")
    void null_origin_is_still_refused() throws Exception {
        MvcResult r = decide("null", "allow");

        // Deliberate. Sandboxed iframes and data:/file: documents also send
        // "null"; accepting it with allowCredentials=true would be a real hole.
        assertThat(r.getResponse().getStatus()).isEqualTo(403);
        assertThat(r.getResponse().getHeader("Location")).isNull();
    }

    @Test
    @DisplayName("the consent CSRF token still guards the form — a missing token is refused")
    void missing_csrf_token_is_still_refused() throws Exception {
        MvcResult r = mvc.perform(post("/t/" + tenant.getSlug() + "/oauth2/authorize/decide")
                        .cookie(session)
                        .header("Origin", SAME_ORIGIN)
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("client_id", clientId)
                        .param("redirect_uri", REDIRECT_URI)
                        .param("scope", "openid")
                        .param("state", "st-123")
                        .param("decision", "allow"))
                .andReturn();

        assertThat(r.getResponse().getHeader("Location"))
                .as("without its CSRF token the decision must never mint a code")
                .satisfiesAnyOf(
                        loc -> assertThat(loc).isNull(),
                        loc -> assertThat(loc).doesNotContain("code="));
    }
}
