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

/**
 * With dynamic registration switched off — the DEFAULT — the server must
 * refuse legibly and say nothing about the endpoint in discovery.
 *
 * <p>This suite exists because its absence shipped a bug. The companion
 * {@link DynamicClientUpdateIntegrationTest} turns the flag ON, so every test
 * ran against the enabled path and the disabled path was never exercised at
 * all. On staging it answered <strong>500 "An unexpected error occurred"</strong>:
 * the refusal threw {@code OidcAuthorizationException}, whose
 * {@code @ExceptionHandler} lives on a different controller, so nothing
 * caught it.
 *
 * <p>A feature flag has two sides. Testing only the side you just built is
 * how the other one reaches production.
 */
@SpringBootTest
@AutoConfigureMockMvc
@Testcontainers
@EnabledIfSystemProperty(named = "tests.integration", matches = "true")
@DisplayName("Dynamic registration, switched off (the default)")
class DynamicRegistrationDisabledIntegrationTest {

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
        // Deliberately NOT setting dynamic-registration-enabled: the default
        // is what this suite is about.
    }

    private static final ObjectMapper JSON = new ObjectMapper();

    @Autowired MockMvc mvc;
    @Autowired TenantRepository tenants;

    private Tenant tenant;

    @BeforeEach
    void seed() {
        String tag = UUID.randomUUID().toString().substring(0, 8);
        tenant = tenants.saveAndFlush(Tenant.builder()
                .slug("dcroff-" + tag).name("dcroff-" + tag).displayName("dcroff-" + tag).build());
    }

    @Test
    @DisplayName("registration is refused with 403 and a reason, not a 500")
    void refusesLegibly() throws Exception {
        MvcResult res = mvc.perform(post("/t/" + tenant.getSlug() + "/oauth2/register")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"redirect_uris\":[\"https://rp.example.com/cb\"]}")).andReturn();

        assertThat(res.getResponse().getStatus())
                .as("500 told the caller nothing and looked like an outage")
                .isEqualTo(403);

        JsonNode body = JSON.readTree(res.getResponse().getContentAsString());
        assertThat(body.get("error").asText()).isEqualTo("access_denied");
        assertThat(body.get("error_description").asText())
                .as("the refusal must say the server does not offer this, so the caller "
                    + "does not retry with better credentials forever")
                .contains("not enabled");
    }

    @Test
    @DisplayName("discovery does not advertise an endpoint that refuses everyone")
    void discoveryStaysQuiet() throws Exception {
        MvcResult res = mvc.perform(
                get("/t/" + tenant.getSlug() + "/.well-known/openid-configuration")).andReturn();

        JsonNode doc = JSON.readTree(res.getResponse().getContentAsString());
        assertThat(doc.has("registration_endpoint"))
                .as("it was advertised unconditionally while returning 403 to every caller")
                .isFalse();
    }
}
