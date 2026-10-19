package tech.cwvermaak.weldforge.integration;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.core.io.ClassPathResource;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import tech.cwvermaak.weldforge.model.AuthProvider;
import tech.cwvermaak.weldforge.model.Tenant;
import tech.cwvermaak.weldforge.model.User;
import tech.cwvermaak.weldforge.repository.TenantRepository;
import tech.cwvermaak.weldforge.repository.UserRepository;

import java.nio.charset.StandardCharsets;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * The name typed into the sign-up form is the account's display name.
 *
 * <p>Before this, registration stored it only as the username and left
 * {@code users.name} null. The name claim and userinfo read {@code users.name},
 * so a self-registered account reached every relying party with no name, and
 * apps showed the email address instead. V69 fills in the accounts made before
 * the fix, and nothing else.
 */
@SpringBootTest
@AutoConfigureMockMvc
@Testcontainers
@EnabledIfSystemProperty(named = "tests.integration", matches = "true")
@DisplayName("Sign-up keeps the name as the display name")
class RegisterDisplayNameIntegrationTest {

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
    @Autowired JdbcTemplate jdbc;

    private Tenant tenant;
    private String tag;

    @BeforeEach
    void seed() {
        tag = UUID.randomUUID().toString().substring(0, 8);
        tenant = tenants.saveAndFlush(Tenant.builder()
                .slug("names-" + tag).name("names-" + tag).displayName("names-" + tag).build());
    }

    @Test
    @DisplayName("registering stores the name, trimmed, as the display name")
    void registerStoresName() throws Exception {
        String email = "maryke-" + tag + "@test.example";
        mvc.perform(post("/api/auth/register")
                        .header("X-Tenant-Slug", tenant.getSlug())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"name\":\"  Maryke Nell \",\"email\":\"" + email
                                 + "\",\"password\":\"" + PASSWORD + "\"}"))
                .andExpect(status().is2xxSuccessful());

        User user = users.findByTenant_SlugAndEmailIgnoreCase(tenant.getSlug(), email).orElseThrow();
        assertThat(user.getName()).isEqualTo("Maryke Nell");
    }

    @Test
    @DisplayName("V69 names self-registered accounts from their username, and touches nothing else")
    void migrationBackfillsOnlySelfRegistered() throws Exception {
        User selfRegistered = save("Nate Example", "nate-" + tag + "@test.example", "local", null);
        String invitedEmail = "invited-" + tag + "@test.example";
        User invited = save(invitedEmail, invitedEmail, invitedEmail, null);
        User alreadyNamed = save("old-username-" + tag, "named-" + tag + "@test.example", "local", "Kept Name");

        String sql = new ClassPathResource("db/migration/V69__self_registered_display_name.sql")
                .getContentAsString(StandardCharsets.UTF_8);
        jdbc.execute(sql);

        assertThat(nameOf(selfRegistered)).isEqualTo("Nate Example");
        assertThat(nameOf(invited)).as("an admin-invited user's username is an email, not a name").isNull();
        assertThat(nameOf(alreadyNamed)).isEqualTo("Kept Name");
    }

    private User save(String username, String email, String providerId, String name) {
        return users.saveAndFlush(User.builder()
                .tenant(tenant)
                .username(username)
                .email(email)
                .name(name)
                .provider(AuthProvider.LOCAL)
                .providerId(providerId)
                .build());
    }

    private String nameOf(User user) {
        return jdbc.queryForObject("SELECT name FROM users WHERE id = ?", String.class, user.getId());
    }
}
