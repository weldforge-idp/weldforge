package tech.cwvermaak.weldforge.integration;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
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
import tech.cwvermaak.weldforge.model.Tenant;
import tech.cwvermaak.weldforge.repository.TenantRepository;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;

/**
 * A dynamically registered client can update its own registration
 * (RFC 7592 §2.2).
 *
 * <p>The registration response has advertised a
 * {@code registration_client_uri} since it was written, and GET and DELETE
 * answered on it — but there was no PUT. We handed every client a management
 * URL on which it could read and destroy its registration and not change it.
 * A client needing one more redirect URI had to delete itself and register
 * again, minting a new {@code client_id} and breaking every token already
 * issued to it.
 *
 * <p>The Dynamic OP conformance profile exercises this directly, which is why
 * it was a standing certification blocker.
 */
@SpringBootTest
@AutoConfigureMockMvc
@Testcontainers
@EnabledIfSystemProperty(named = "tests.integration", matches = "true")
@DisplayName("RFC 7592: a client can manage its own registration")
class DynamicClientUpdateIntegrationTest {

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
        registry.add("app.security.rate-limit.enabled", () -> "false");
        // Off by default; this suite is about the endpoint being usable.
        registry.add("app.security.oidc.dynamic-registration-enabled", () -> "true");
    }

    private static final ObjectMapper JSON = new ObjectMapper();

    @Autowired MockMvc mvc;
    @Autowired TenantRepository tenants;

    private Tenant tenant;
    private String clientId;
    private String registrationToken;

    @BeforeEach
    void registerClient() throws Exception {
        String tag = UUID.randomUUID().toString().substring(0, 8);
        tenant = tenants.saveAndFlush(Tenant.builder()
                .slug("dcr-" + tag).name("dcr-" + tag).displayName("dcr-" + tag).build());

        MvcResult res = mvc.perform(post("/t/" + tenant.getSlug() + "/oauth2/register")
                .contentType(MediaType.APPLICATION_JSON)
                .content("""
                    {
                      "client_name": "Dynamic RP",
                      "redirect_uris": ["https://rp.example.com/cb"],
                      "grant_types": ["authorization_code"],
                      "scope": "openid profile",
                      "token_endpoint_auth_method": "client_secret_basic"
                    }
                    """)).andReturn();

        assertThat(res.getResponse().getStatus()).isIn(200, 201);
        JsonNode body = JSON.readTree(res.getResponse().getContentAsString());
        clientId = body.get("client_id").asText();
        registrationToken = body.get("registration_access_token").asText();

        assertThat(body.get("registration_client_uri").asText())
                .as("the management URI we are about to exercise")
                .endsWith("/oauth2/register/" + clientId);
    }

    private MvcResult putRegistration(String token, String json) throws Exception {
        var req = put("/t/" + tenant.getSlug() + "/oauth2/register/" + clientId)
                .contentType(MediaType.APPLICATION_JSON)
                .content(json);
        if (token != null) req = req.header("Authorization", "Bearer " + token);
        return mvc.perform(req).andReturn();
    }

    private String body(String redirectUris) {
        return """
            {
              "client_id": "%s",
              "client_name": "Dynamic RP",
              "redirect_uris": %s,
              "grant_types": ["authorization_code"],
              "scope": "openid profile",
              "token_endpoint_auth_method": "client_secret_basic"
            }
            """.formatted(clientId, redirectUris);
    }

    @Test
    @DisplayName("adds a redirect URI without re-registering, so client_id survives")
    void updatesRedirectUris() throws Exception {
        MvcResult res = putRegistration(registrationToken,
                body("[\"https://rp.example.com/cb\", \"https://rp.example.com/cb2\"]"));

        assertThat(res.getResponse().getStatus()).isEqualTo(200);
        JsonNode body = JSON.readTree(res.getResponse().getContentAsString());
        assertThat(body.get("client_id").asText())
                .as("a new client_id would break every token already issued")
                .isEqualTo(clientId);

        // Read it back through GET rather than trusting the PUT's own echo.
        MvcResult read = mvc.perform(get("/t/" + tenant.getSlug() + "/oauth2/register/" + clientId)
                .header("Authorization", "Bearer " + registrationToken)).andReturn();
        JsonNode after = JSON.readTree(read.getResponse().getContentAsString());
        assertThat(after.get("redirect_uris").toString()).contains("cb2");
    }

    @Test
    @DisplayName("replaces rather than merges — §2.2 treats an omitted field as removed")
    void replacesRatherThanMerges() throws Exception {
        putRegistration(registrationToken,
                body("[\"https://rp.example.com/cb\", \"https://rp.example.com/cb2\"]"));
        // Now send only the original URI back.
        putRegistration(registrationToken, body("[\"https://rp.example.com/cb\"]"));

        MvcResult read = mvc.perform(get("/t/" + tenant.getSlug() + "/oauth2/register/" + clientId)
                .header("Authorization", "Bearer " + registrationToken)).andReturn();
        JsonNode after = JSON.readTree(read.getResponse().getContentAsString());
        assertThat(after.get("redirect_uris").toString())
                .as("merge semantics would have kept cb2, which the client believes it dropped")
                .doesNotContain("cb2");
    }

    @Test
    @DisplayName("without the registration token it is refused")
    void requiresTheRegistrationToken() throws Exception {
        MvcResult res = putRegistration(null, body("[\"https://rp.example.com/cb\"]"));
        assertThat(res.getResponse().getStatus()).isIn(401, 403);
    }

    @Test
    @DisplayName("a wrong registration token is refused")
    void refusesAWrongToken() throws Exception {
        MvcResult res = putRegistration("not-the-right-token",
                body("[\"https://rp.example.com/cb\"]"));
        assertThat(res.getResponse().getStatus()).isIn(401, 403);
    }

    @Test
    @DisplayName("a mismatched client_id in the body is refused, per §2.2")
    void refusesMismatchedClientId() throws Exception {
        MvcResult res = putRegistration(registrationToken, """
            {
              "client_id": "some-other-client",
              "redirect_uris": ["https://rp.example.com/cb"]
            }
            """);
        assertThat(res.getResponse().getStatus()).isEqualTo(400);
    }

    @Test
    @DisplayName("an empty redirect_uris is refused rather than leaving a client nobody can use")
    void refusesEmptyRedirectUris() throws Exception {
        MvcResult res = putRegistration(registrationToken, body("[]"));
        assertThat(res.getResponse().getStatus()).isEqualTo(400);
    }

    @Test
    @DisplayName("a client cannot promote itself from confidential to public")
    void refusesAuthMethodChange() throws Exception {
        MvcResult res = putRegistration(registrationToken, """
            {
              "client_id": "%s",
              "redirect_uris": ["https://rp.example.com/cb"],
              "token_endpoint_auth_method": "none"
            }
            """.formatted(clientId));
        assertThat(res.getResponse().getStatus()).isEqualTo(400);
    }
}
