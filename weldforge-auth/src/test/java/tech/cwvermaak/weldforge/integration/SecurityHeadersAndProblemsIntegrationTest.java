package tech.cwvermaak.weldforge.integration;

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

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

/**
 * Sprint 6 acceptance through the real filter chain (CONF-7.2, CONF-7.3):
 * security headers on every response, Problem Details on {@code /api/**},
 * and the protocol endpoints' own error formats left alone.
 */
@SpringBootTest
@AutoConfigureMockMvc
@Testcontainers
@EnabledIfSystemProperty(named = "tests.integration", matches = "true")
@DisplayName("Security headers and RFC 9457 problems through the full chain")
class SecurityHeadersAndProblemsIntegrationTest {

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
    }

    @Autowired MockMvc mvc;

    private static void assertSecurityHeaders(MvcResult r) {
        String csp = r.getResponse().getHeader("Content-Security-Policy");
        assertThat(csp).as("CSP on %s", r.getRequest().getRequestURI())
                .contains("default-src 'self'")
                .contains("frame-ancestors 'none'")
                .containsPattern("script-src 'self' 'nonce-[A-Za-z0-9+/=]+'");
        assertThat(r.getResponse().getHeader("Referrer-Policy")).isEqualTo("no-referrer");
        assertThat(r.getResponse().getHeader("X-Content-Type-Options")).isEqualTo("nosniff");
    }

    // ---- CONF-7.2 ------------------------------------------------------

    @Test
    @DisplayName("Security headers are present on a public protocol response")
    void headers_on_discovery() throws Exception {
        assertSecurityHeaders(mvc.perform(get("/t/default/.well-known/openid-configuration")).andReturn());
    }

    @Test
    @DisplayName("Security headers are present on an error response too")
    void headers_on_error() throws Exception {
        MvcResult r = mvc.perform(get("/api/admin/tenants")).andReturn();
        assertThat(r.getResponse().getStatus()).isEqualTo(401);
        assertSecurityHeaders(r);
    }

    @Test
    @DisplayName("Each response gets its own nonce")
    void nonce_per_response() throws Exception {
        String a = mvc.perform(get("/t/default/.well-known/openid-configuration")).andReturn()
                .getResponse().getHeader("Content-Security-Policy");
        String b = mvc.perform(get("/t/default/.well-known/openid-configuration")).andReturn()
                .getResponse().getHeader("Content-Security-Policy");
        assertThat(a).isNotEqualTo(b);
    }

    // ---- CONF-7.2: pages render under their own policy --------------------
    // These prove the part unit tests cannot: that the nonce a controller puts
    // in the page while rendering is the one the header writer emits when the
    // response commits, through the real filter chain's request wrappers.

    @Autowired tech.cwvermaak.weldforge.repository.TenantRepository tenantRepository;
    @Autowired tech.cwvermaak.weldforge.repository.UserRepository userRepository;
    @Autowired tech.cwvermaak.weldforge.repository.OidcClientRepository oidcClientRepository;
    @Autowired tech.cwvermaak.weldforge.service.JwtService jwtService;

    private static String headerNonce(MvcResult r) {
        java.util.regex.Matcher m = java.util.regex.Pattern.compile("script-src 'self' 'nonce-([^']+)'")
                .matcher(r.getResponse().getHeader("Content-Security-Policy"));
        assertThat(m.find()).isTrue();
        return m.group(1);
    }

    private static void assertInlineBlocksCarry(String html, String nonce) {
        java.util.regex.Matcher blocks = java.util.regex.Pattern.compile("<(style|script)([^>]*)>").matcher(html);
        int seen = 0;
        while (blocks.find()) {
            seen++;
            assertThat(blocks.group(2)).as("<%s>", blocks.group(1)).contains("nonce=\"" + nonce + "\"");
        }
        assertThat(seen).isPositive();
    }

    @Test
    @DisplayName("The tenant verification page renders (it answered 400 in production) under its policy")
    void verify_contact_page_end_to_end() throws Exception {
        MvcResult r = mvc.perform(get("/api/auth/tenants/verify-contact-page").param("token", "tok-123"))
                .andReturn();

        assertThat(r.getResponse().getStatus()).isEqualTo(200);
        assertThat(r.getResponse().getContentType()).startsWith("text/html");
        String html = r.getResponse().getContentAsString();
        assertThat(html).contains("Confirm tenant ownership").doesNotContain("Conversion");
        assertInlineBlocksCarry(html, headerNonce(r));
        assertSecurityHeaders(r);
    }

    @Test
    @DisplayName("The hosted sign-in page's stylesheet carries the response's nonce")
    void hosted_login_end_to_end() throws Exception {
        MvcResult r = mvc.perform(get("/login/")).andReturn();

        assertThat(r.getResponse().getStatus()).isEqualTo(200);
        assertInlineBlocksCarry(r.getResponse().getContentAsString(), headerNonce(r));
    }

    @Test
    @org.springframework.transaction.annotation.Transactional
    @DisplayName("The consent page renders under its own policy for a signed-in user")
    void consent_page_end_to_end() throws Exception {
        tech.cwvermaak.weldforge.model.Tenant tenant = tenantRepository.findBySlug("default").orElseThrow();
        tech.cwvermaak.weldforge.model.User user = userRepository.save(tech.cwvermaak.weldforge.model.User.builder()
                .tenant(tenant)
                .username("csp-consent-user")
                .email("csp-consent@test.com")
                .provider(tech.cwvermaak.weldforge.model.AuthProvider.LOCAL)
                .providerId("csp-consent-user")
                .active(true)
                .build());
        oidcClientRepository.save(tech.cwvermaak.weldforge.model.OidcClient.builder()
                .tenant(tenant)
                .clientId("csp-consent-rp")
                .clientSecret("rp-secret")
                .name("CSP Consent RP")
                .redirectUris("https://app.test/callback")
                .scopes("openid email")
                .grantTypes("authorization_code")
                .requirePkce(false)
                .build());
        String session = jwtService.generateAccessToken(user.getEmail(), tenant.getId(), tenant.getSlug(),
                false, user.getTokenVersion(), null, null, "NONE",
                "https://sso.weldforge.org/t/default", java.util.List.of("pwd"),
                java.util.UUID.randomUUID().toString());

        MvcResult r = mvc.perform(get("/t/default/oauth2/authorize")
                        .header("Authorization", "Bearer " + session)
                        .param("response_type", "code")
                        .param("client_id", "csp-consent-rp")
                        .param("redirect_uri", "https://app.test/callback")
                        .param("scope", "openid email")
                        .param("state", "st-1"))
                .andReturn();

        assertThat(r.getResponse().getStatus()).isEqualTo(200);
        String html = r.getResponse().getContentAsString();
        assertThat(html).contains("CSP Consent RP wants to access your account");
        assertInlineBlocksCarry(html, headerNonce(r));
        assertThat(html).doesNotContainPattern("\\son[a-z]+\\s*=").doesNotContainPattern("\\sstyle\\s*=");
        assertSecurityHeaders(r);
    }

    // ---- CONF-7.3 ------------------------------------------------------

    @Test
    @DisplayName("An /api/** error is a problem document, legacy members kept")
    void api_errors_are_problems() throws Exception {
        MvcResult r = mvc.perform(post("/api/auth/login")
                        .header("X-Tenant-Slug", "default")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{not json"))
                .andReturn();

        assertThat(r.getResponse().getStatus()).isEqualTo(400);
        assertThat(r.getResponse().getContentType()).startsWith("application/problem+json");
        String body = r.getResponse().getContentAsString();
        assertThat(body)
                .contains("\"type\":\"tag:weldforge.org,2026:problem:bad_request\"")
                .contains("\"title\":\"Bad Request\"")
                .contains("\"status\":400")
                .contains("\"detail\":")
                // What the admin portal and proxies read today.
                .contains("\"error\":\"bad_request\"")
                .contains("\"message\":");
    }

    @Test
    @DisplayName("An unauthenticated /api/** call is a 401 problem document")
    void unauthenticated_api_is_problem() throws Exception {
        MvcResult r = mvc.perform(get("/api/admin/tenants")).andReturn();

        assertThat(r.getResponse().getContentType()).startsWith("application/problem+json");
        assertThat(r.getResponse().getContentAsString())
                .contains("\"status\":401")
                .contains("\"type\":\"tag:weldforge.org,2026:problem:unauthorized\"");
    }

    @Test
    @DisplayName("A failed OAuth2 token request still answers {error, error_description}")
    void oauth_errors_unchanged() throws Exception {
        MvcResult r = mvc.perform(post("/t/default/oauth2/token")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .content("grant_type=client_credentials&client_id=no-such-client&client_secret=x"))
                .andReturn();

        assertThat(r.getResponse().getStatus()).isBetween(400, 401);
        assertThat(r.getResponse().getContentType()).doesNotContain("problem");
        assertThat(r.getResponse().getContentAsString())
                .contains("\"error\"")
                .doesNotContain("\"type\":\"tag:");
    }

    @Test
    @DisplayName("A failed SCIM request still answers a SCIM error response")
    void scim_errors_unchanged() throws Exception {
        MvcResult r = mvc.perform(get("/scim/v2/default/Users")).andReturn();

        assertThat(r.getResponse().getStatus()).isEqualTo(401);
        assertThat(r.getResponse().getContentAsString())
                .contains("urn:ietf:params:scim:api:messages:2.0:Error")
                .doesNotContain("\"type\":\"tag:");
    }
}
