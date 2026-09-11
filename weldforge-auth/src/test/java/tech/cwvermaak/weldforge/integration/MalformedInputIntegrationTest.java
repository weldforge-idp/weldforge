package tech.cwvermaak.weldforge.integration;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import tech.cwvermaak.weldforge.model.AdminRole;
import tech.cwvermaak.weldforge.model.AuthProvider;
import tech.cwvermaak.weldforge.model.Tenant;
import tech.cwvermaak.weldforge.model.User;
import tech.cwvermaak.weldforge.repository.TenantRepository;
import tech.cwvermaak.weldforge.repository.UserRepository;
import tech.cwvermaak.weldforge.service.JwtService;

import java.util.List;
import java.util.UUID;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.request;

/**
 * B-API-2: every JSON endpoint under {@code /api/auth/**} and
 * {@code /api/public/**}, fed every shape of bad body a client can send, must
 * answer 4xx with a problem document -- never 500.
 *
 * <p>Found 2026-09-11 on staging: registering with {@code username} instead of
 * {@code name} reached the database and came back as a 500, because nothing
 * validated the request. A 500 tells a client nothing, pages whoever is on
 * call, and hides the difference between "your request is wrong" and "we are
 * broken".
 */
@SpringBootTest
@AutoConfigureMockMvc
@Testcontainers
@EnabledIfSystemProperty(named = "tests.integration", matches = "true")
@DisplayName("Malformed input: 4xx problem documents, never 500")
class MalformedInputIntegrationTest {

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
        // Otherwise the limiter answers 429 and hides what the endpoint does.
        registry.add("app.security.rate-limit.enabled", () -> "false");
    }

    @Autowired MockMvc mvc;
    @Autowired TenantRepository tenants;
    @Autowired UserRepository users;
    @Autowired JwtService jwtService;

    private String bearer;

    @BeforeEach
    void signedInUser() {
        if (bearer != null) return;
        Tenant home = tenants.findBySlug("default").orElseThrow();
        String tag = UUID.randomUUID().toString().substring(0, 8);
        User u = users.save(User.builder()
                .tenant(home).username("u-" + tag).email("u-" + tag + "@test.example")
                .provider(AuthProvider.LOCAL).providerId("u-" + tag).active(true)
                .password("$2a$12$abcdefghijklmnopqrstuuJQ1n7m0T0H0x3mZ0l8G6d2kqY5y2m3a")
                .build());
        bearer = "Bearer " + jwtService.generateAccessToken(u.getEmail(), home.getId(), home.getSlug(),
                false, u.getTokenVersion(), null, null, AdminRole.NONE.name(),
                "https://sso.weldforge.org/t/default", List.of("pwd"), null);
    }

    /** Every body shape a careless or hostile client sends. */
    static final List<String> BODIES = List.of(
            "",
            "null",
            "[]",
            "\"a string\"",
            "{",
            "{}",
            "{\"unexpected\":1}",
            // every field the endpoints read, all null
            "{\"name\":null,\"email\":null,\"password\":null,\"identifier\":null,\"token\":null,"
                    + "\"code\":null,\"challengeToken\":null,\"type\":null,\"backupCode\":null,"
                    + "\"currentPassword\":null,\"newPassword\":null,\"phoneNumber\":null,\"credential\":null,"
                    + "\"webauthnResponse\":null,\"tier\":null,\"contactEmail\":null,\"tenantSlug\":null}",
            // every field blank
            "{\"name\":\"\",\"email\":\"\",\"password\":\"\",\"identifier\":\"\",\"token\":\"\",\"code\":\"\","
                    + "\"challengeToken\":\"\",\"type\":\"\",\"currentPassword\":\"\",\"newPassword\":\"\","
                    + "\"phoneNumber\":\"\",\"credential\":\"\",\"tier\":\"\",\"contactEmail\":\"\",\"tenantSlug\":\"\"}",
            // every field the wrong type
            "{\"name\":123,\"email\":{},\"password\":[1],\"identifier\":true,\"token\":1.5,\"code\":{},"
                    + "\"challengeToken\":[],\"type\":\"NOT_A_FACTOR\",\"currentPassword\":7,\"newPassword\":false,"
                    + "\"phoneNumber\":{},\"credential\":42,\"tier\":[],\"termsAccepted\":\"maybe\"}",
            // plausible-looking but wrong values
            "{\"name\":\"x\",\"email\":\"not-an-email\",\"password\":\"x\",\"identifier\":\"nobody\","
                    + "\"token\":\"not-a-token\",\"code\":\"12\",\"challengeToken\":\"not.a.jwt\",\"type\":\"TOTP\"}",
            // past the first check: a real-looking id with a mistyped or bogus rest
            "{\"factorId\":1,\"code\":{}}",
            "{\"factorId\":\"abc\",\"code\":\"123456\"}",
            "{\"factorId\":999999,\"code\":\"123456\"}",
            "{\"ceremonyKey\":\"made-up\",\"publicKeyCredential\":\"{not json\"}",
            "{\"token\":\"no-such-token\",\"newPassword\":\"correct horse battery staple\"}");

    record Endpoint(HttpMethod method, String path, boolean authenticated) {
        @Override public String toString() { return method + " " + path + (authenticated ? " (signed in)" : ""); }
    }

    static final List<Endpoint> ENDPOINTS = List.of(
            new Endpoint(HttpMethod.POST, "/api/auth/register", false),
            new Endpoint(HttpMethod.POST, "/api/auth/login", false),
            new Endpoint(HttpMethod.POST, "/api/auth/verify-email", false),
            new Endpoint(HttpMethod.POST, "/api/auth/resend-verification", false),
            new Endpoint(HttpMethod.POST, "/api/auth/forgot-password", false),
            new Endpoint(HttpMethod.POST, "/api/auth/reset-password", false),
            new Endpoint(HttpMethod.POST, "/api/auth/tenants/verify-contact", false),
            new Endpoint(HttpMethod.POST, "/api/auth/mfa/verify", false),
            new Endpoint(HttpMethod.POST, "/api/auth/mfa/webauthn/assertion/start", false),
            new Endpoint(HttpMethod.POST, "/api/public/orders", false),
            new Endpoint(HttpMethod.PUT, "/api/auth/me", true),
            new Endpoint(HttpMethod.POST, "/api/auth/change-password", true),
            new Endpoint(HttpMethod.POST, "/api/auth/mfa/totp/activate", true),
            new Endpoint(HttpMethod.POST, "/api/auth/mfa/sms/enroll", true),
            new Endpoint(HttpMethod.POST, "/api/auth/mfa/sms/activate", true),
            new Endpoint(HttpMethod.POST, "/api/auth/mfa/sms/send", true),
            new Endpoint(HttpMethod.POST, "/api/auth/mfa/reset", true),
            new Endpoint(HttpMethod.POST, "/api/auth/mfa/webauthn/registration/start", true),
            new Endpoint(HttpMethod.POST, "/api/auth/mfa/webauthn/registration/finish", true));

    static Stream<Arguments> cases() {
        return ENDPOINTS.stream().flatMap(e -> BODIES.stream().map(b -> Arguments.of(e, b)));
    }

    @ParameterizedTest(name = "{0} <- {1}")
    @MethodSource("cases")
    void never_500(Endpoint endpoint, String body) throws Exception {
        MockHttpServletRequestBuilder req = request(endpoint.method(), endpoint.path())
                .header("X-Tenant-Slug", "default")
                .contentType(MediaType.APPLICATION_JSON)
                .content(body);
        if (endpoint.authenticated()) req.header("Authorization", bearer);

        MvcResult r = mvc.perform(req).andReturn();
        int status = r.getResponse().getStatus();

        assertThat(status)
                .as("%s with body %s answered %d: %s", endpoint, body, status,
                        r.getResponse().getContentAsString())
                .isLessThan(500);
        if (status >= 400) {
            assertThat(r.getResponse().getContentType())
                    .as("%s with body %s: an error is a problem document", endpoint, body)
                    .startsWith("application/problem+json");
        }
    }

    // ---- the specific contract for registration ------------------------------

    @Test
    @DisplayName("register names the missing field instead of failing at the database")
    void register_names_the_missing_field() throws Exception {
        MvcResult r = mvc.perform(request(HttpMethod.POST, "/api/auth/register")
                        .header("X-Tenant-Slug", "default")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"alice\",\"email\":\"alice@test.example\","
                                + "\"password\":\"correct horse battery staple\"}"))
                .andReturn();

        assertThat(r.getResponse().getStatus()).isEqualTo(400);
        assertThat(r.getResponse().getContentType()).startsWith("application/problem+json");
        assertThat(r.getResponse().getContentAsString())
                .contains("validation_error")
                .contains("\"errors\"")
                .contains("\"field\":\"name\"");
    }

    @Test
    @DisplayName("register refuses an address that is not an email")
    void register_refuses_non_email() throws Exception {
        MvcResult r = mvc.perform(request(HttpMethod.POST, "/api/auth/register")
                        .header("X-Tenant-Slug", "default")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"name\":\"bob\",\"email\":\"bob\",\"password\":\"correct horse battery staple\"}"))
                .andReturn();

        assertThat(r.getResponse().getStatus()).isEqualTo(400);
        assertThat(r.getResponse().getContentAsString()).contains("email");
        assertThat(users.findAll()).noneMatch(u -> "bob".equals(u.getEmail()));
    }

    @Test
    @DisplayName("a well-formed registration still succeeds")
    void register_happy_path_unchanged() throws Exception {
        String tag = UUID.randomUUID().toString().substring(0, 8);
        MvcResult r = mvc.perform(request(HttpMethod.POST, "/api/auth/register")
                        .header("X-Tenant-Slug", "default")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"name\":\"carol-" + tag + "\",\"email\":\"carol-" + tag + "@test.example\","
                                + "\"password\":\"correct horse battery staple\"}"))
                .andReturn();

        assertThat(r.getResponse().getStatus()).isEqualTo(200);
    }

    @Test
    @DisplayName("an order missing required fields is refused with the fields named")
    void order_validation_is_enforced() throws Exception {
        MvcResult r = mvc.perform(request(HttpMethod.POST, "/api/public/orders")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"tier\":\"starter\",\"termsAccepted\":true}"))
                .andReturn();

        assertThat(r.getResponse().getStatus()).isEqualTo(400);
        assertThat(r.getResponse().getContentAsString())
                .contains("validation_error")
                .contains("contactEmail");
    }

    // ---- the anonymous callers the app-key gate used to refuse ---------------

    @Test
    @DisplayName("the public order funnel is reachable without an app key (was a production 403)")
    void order_funnel_reachable() throws Exception {
        MvcResult r = mvc.perform(request(HttpMethod.POST, "/api/public/orders")
                        .contentType(MediaType.APPLICATION_JSON).content("{}"))
                .andReturn();

        assertThat(r.getResponse().getStatus()).isEqualTo(400);
        assertThat(r.getResponse().getContentAsString()).doesNotContain("x-app-authorization");
    }

    @ParameterizedTest(name = "POST /api/webhooks/{0} reaches the signature check")
    @org.junit.jupiter.params.provider.ValueSource(strings = {"stripe", "paddle", "payfast", "yoco"})
    void webhooks_reach_signature_check(String gateway) throws Exception {
        MvcResult r = mvc.perform(request(HttpMethod.POST, "/api/webhooks/" + gateway)
                        .contentType(MediaType.APPLICATION_JSON).content("{\"id\":\"evt_test\"}"))
                .andReturn();

        // Refused for what it is -- unsigned -- not for lacking an app key.
        assertThat(r.getResponse().getStatus()).isNotEqualTo(403).isLessThan(500);
        assertThat(r.getResponse().getContentAsString()).doesNotContain("x-app-authorization");
    }
}
