package tech.cwvermaak.weldforge.integration;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import tech.cwvermaak.weldforge.model.AdminRole;
import tech.cwvermaak.weldforge.model.AuthProvider;
import tech.cwvermaak.weldforge.model.User;
import tech.cwvermaak.weldforge.repository.TenantRepository;
import tech.cwvermaak.weldforge.repository.UserRepository;

import java.time.LocalDateTime;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

/**
 * Performance and penetration test 2026-11-16 (Proboulos WF-18): an unknown,
 * disabled or locked account was refused before the password compare, so it
 * answered in milliseconds while a real account with a wrong password spent a
 * BCrypt compare. Timing the answers told an attacker which addresses hold an
 * account.
 *
 * <p>Counting compares rather than timing them keeps this deterministic: every
 * refusal must cost exactly one, the same as a wrong password.
 */
@SpringBootTest
@AutoConfigureMockMvc
@Testcontainers
@EnabledIfSystemProperty(named = "tests.integration", matches = "true")
@DisplayName("Every refused sign-in costs one password compare")
class LoginRefusalCostIntegrationTest {

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

    private static final String PASSWORD = "Correct-Horse-Battery-9";

    static final AtomicInteger COMPARES = new AtomicInteger();

    @TestConfiguration
    static class CountingConfig {
        @Bean
        @Primary
        PasswordEncoder countingPasswordEncoder() {
            PasswordEncoder delegate = new BCryptPasswordEncoder(4);
            return new PasswordEncoder() {
                @Override public String encode(CharSequence raw) { return delegate.encode(raw); }
                @Override public boolean upgradeEncoding(String encoded) { return false; }
                @Override public boolean matches(CharSequence raw, String encoded) {
                    COMPARES.incrementAndGet();
                    return delegate.matches(raw, encoded);
                }
            };
        }
    }

    @Autowired MockMvc mvc;
    @Autowired TenantRepository tenants;
    @Autowired UserRepository users;
    @Autowired PasswordEncoder encoder;

    @BeforeEach
    void reset() {
        COMPARES.set(0);
    }

    private User user(boolean active, LocalDateTime lockedUntil, boolean withPassword) {
        String tag = UUID.randomUUID().toString().substring(0, 8);
        return users.save(User.builder()
                .tenant(tenants.findBySlug("default").orElseThrow())
                .username("probe-" + tag)
                .email("probe-" + tag + "@test.example")
                .password(withPassword ? encoder.encode(PASSWORD) : null)
                .provider(AuthProvider.LOCAL)
                .providerId("probe-" + tag)
                .emailVerified(true)
                .active(active)
                .lockedUntil(lockedUntil)
                .adminRole(AdminRole.NONE)
                .build());
    }

    /** Signs in and returns how many compares the request cost; asserts the 401. */
    private int comparesFor(String identifier, String password) throws Exception {
        COMPARES.set(0);
        int status = mvc.perform(post("/api/auth/login")
                        .header("X-Tenant-Slug", "default")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"identifier\":\"" + identifier + "\",\"password\":\"" + password + "\"}"))
                .andReturn().getResponse().getStatus();
        assertThat(status).as("refused").isEqualTo(401);
        return COMPARES.get();
    }

    @Test
    @DisplayName("a wrong password costs one compare (control)")
    void wrongPassword() throws Exception {
        assertThat(comparesFor(user(true, null, true).getEmail(), "Wrong-Password-123")).isEqualTo(1);
    }

    @Test
    @DisplayName("an unknown address costs one compare")
    void unknownAddress() throws Exception {
        assertThat(comparesFor("nobody-" + UUID.randomUUID() + "@test.example", PASSWORD)).isEqualTo(1);
    }

    @Test
    @DisplayName("a disabled account costs one compare")
    void disabledAccount() throws Exception {
        assertThat(comparesFor(user(false, null, true).getEmail(), PASSWORD)).isEqualTo(1);
    }

    @Test
    @DisplayName("a locked account costs one compare, and the right password is not confirmed")
    void lockedAccount() throws Exception {
        User u = user(true, LocalDateTime.now().plusMinutes(15), true);
        assertThat(comparesFor(u.getEmail(), PASSWORD)).isEqualTo(1);
    }

    @Test
    @DisplayName("an account with no local password costs one compare")
    void noLocalPassword() throws Exception {
        assertThat(comparesFor(user(true, null, false).getEmail(), PASSWORD)).isEqualTo(1);
    }
}
