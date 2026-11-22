package tech.cwvermaak.weldforge.integration;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
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
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import tech.cwvermaak.weldforge.model.AdminRole;
import tech.cwvermaak.weldforge.model.AuthProvider;
import tech.cwvermaak.weldforge.model.MfaFactor;
import tech.cwvermaak.weldforge.model.MfaFactorType;
import tech.cwvermaak.weldforge.model.User;
import tech.cwvermaak.weldforge.repository.MfaFactorRepository;
import tech.cwvermaak.weldforge.repository.TenantRepository;
import tech.cwvermaak.weldforge.repository.UserRepository;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

/**
 * Security review 2026-11-15 (Proboulos WF-5): wrong passwords and wrong
 * second-factor codes share one failure counter, and the password step
 * cleared it. Anyone holding the password could therefore guess codes
 * without limit: four wrong codes, sign in again, four more.
 */
@SpringBootTest
@AutoConfigureMockMvc
@Testcontainers
@EnabledIfSystemProperty(named = "tests.integration", matches = "true")
@DisplayName("Wrong second-factor codes are not forgiven by signing in again")
class MfaFailureCounterIntegrationTest {

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
        registry.add("app.security.lockout.max-attempts", () -> "5");
    }

    private static final String PASSWORD = "Correct-Horse-Battery-9";

    @Autowired MockMvc mvc;
    @Autowired ObjectMapper json;
    @Autowired TenantRepository tenants;
    @Autowired UserRepository users;
    @Autowired MfaFactorRepository factors;
    @Autowired PasswordEncoder encoder;

    private User userWithSecondFactor() {
        String tag = UUID.randomUUID().toString().substring(0, 8);
        User u = users.save(User.builder()
                .tenant(tenants.findBySlug("default").orElseThrow())
                .username("mfa-" + tag)
                .email("mfa-" + tag + "@test.example")
                .password(encoder.encode(PASSWORD))
                .provider(AuthProvider.LOCAL)
                .providerId("mfa-" + tag)
                .emailVerified(true)
                .active(true)
                .adminRole(AdminRole.NONE)
                .build());
        // A verified SMS factor with no code outstanding: every code is wrong,
        // which is all this test needs.
        factors.save(MfaFactor.builder()
                .user(u)
                .type(MfaFactorType.SMS)
                .label("phone")
                .phoneNumber("+27820000000")
                .enabled(true)
                .verified(true)
                .build());
        return u;
    }

    private MvcResult login(User u) throws Exception {
        return mvc.perform(post("/api/auth/login")
                        .header("X-Tenant-Slug", "default")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"identifier\":\"" + u.getEmail() + "\",\"password\":\"" + PASSWORD + "\"}"))
                .andReturn();
    }

    private int wrongCode(String challengeToken) throws Exception {
        return mvc.perform(post("/api/auth/mfa/verify")
                        .header("X-Tenant-Slug", "default")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"challengeToken\":\"" + challengeToken + "\",\"type\":\"SMS\",\"code\":\"000000\"}"))
                .andReturn().getResponse().getStatus();
    }

    @Test
    @DisplayName("five wrong codes across five sign-ins lock the account")
    void wrongCodesAccumulateAcrossSignIns() throws Exception {
        User u = userWithSecondFactor();

        for (int round = 1; round <= 5; round++) {
            MvcResult r = login(u);
            assertThat(r.getResponse().getStatus()).as("password step, round %d", round).isEqualTo(200);
            JsonNode body = json.readTree(r.getResponse().getContentAsString());
            assertThat(body.path("mfaRequired").asBoolean()).as("second factor asked for").isTrue();
            assertThat(wrongCode(body.path("mfaChallengeToken").asText()))
                    .as("wrong code, round %d", round).isEqualTo(401);
        }

        User after = users.findById(u.getId()).orElseThrow();
        assertThat(after.getLockedUntil()).as("locked after five wrong codes").isNotNull();
        assertThat(login(u).getResponse().getStatus())
                .as("the right password no longer opens a locked account").isEqualTo(401);
    }

    @Test
    @DisplayName("the password step keeps the count when a second factor follows")
    void passwordStepDoesNotClearTheCount() throws Exception {
        User u = userWithSecondFactor();
        JsonNode body = json.readTree(login(u).getResponse().getContentAsString());
        assertThat(wrongCode(body.path("mfaChallengeToken").asText())).isEqualTo(401);
        assertThat(wrongCode(body.path("mfaChallengeToken").asText())).isEqualTo(401);

        assertThat(login(u).getResponse().getStatus()).isEqualTo(200);

        assertThat(users.findById(u.getId()).orElseThrow().getFailedLoginAttempts())
                .as("two wrong codes, still counted after a correct password").isEqualTo(2);
    }
}
