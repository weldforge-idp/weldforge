package tech.cwvermaak.weldforge.integration;

import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import tech.cwvermaak.weldforge.config.tenant.TenantContext;
import tech.cwvermaak.weldforge.model.AdminRole;
import tech.cwvermaak.weldforge.model.AuthProvider;
import tech.cwvermaak.weldforge.model.Tenant;
import tech.cwvermaak.weldforge.model.User;
import tech.cwvermaak.weldforge.model.dto.scim.ScimPatchRequestDto;
import tech.cwvermaak.weldforge.repository.TenantRepository;
import tech.cwvermaak.weldforge.repository.UserRepository;
import tech.cwvermaak.weldforge.service.AdminService;
import tech.cwvermaak.weldforge.service.scim.ScimUserService;

import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

/**
 * Security review 2026-11-15: an account deactivated by SCIM, or deleted by
 * an admin, kept every session it had. /api/auth/refresh never checked
 * whether the user was active and minted fresh access tokens at the user's
 * current token_version; the JWT filter never checked either, and
 * authenticated a token whose user no longer existed; SCIM deactivation
 * revoked nothing.
 */
@SpringBootTest
@AutoConfigureMockMvc
@Testcontainers
@EnabledIfSystemProperty(named = "tests.integration", matches = "true")
@DisplayName("A deactivated user's sessions end")
class DeactivatedUserSessionIntegrationTest {

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

    @Autowired MockMvc mvc;
    @Autowired TenantRepository tenants;
    @Autowired UserRepository users;
    @Autowired PasswordEncoder encoder;
    @Autowired JdbcTemplate jdbc;
    @Autowired ScimUserService scim;
    @Autowired AdminService admin;

    @AfterEach
    void clearContext() {
        TenantContext.clear();
    }

    private Tenant home() {
        return tenants.findBySlug("default").orElseThrow();
    }

    private User user() {
        String tag = UUID.randomUUID().toString().substring(0, 8);
        return users.save(User.builder()
                .tenant(home())
                .username("leaver-" + tag)
                .email("leaver-" + tag + "@test.example")
                .password(encoder.encode(PASSWORD))
                .provider(AuthProvider.LOCAL)
                .providerId("leaver-" + tag)
                .emailVerified(true)
                .active(true)
                .adminRole(AdminRole.NONE)
                .build());
    }

    /** A real sign-in: the access token plus every cookie it set. */
    private record Session(String accessToken, Cookie[] cookies) {}

    private Session signIn(User u) throws Exception {
        MvcResult r = mvc.perform(post("/api/auth/login")
                        .header("X-Tenant-Slug", "default")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"identifier\":\"" + u.getEmail() + "\",\"password\":\"" + PASSWORD + "\"}"))
                .andReturn();
        assertThat(r.getResponse().getStatus()).as("sign-in").isEqualTo(200);
        String body = r.getResponse().getContentAsString();
        String token = body.replaceAll(".*\"token\"\\s*:\\s*\"([^\"]+)\".*", "$1");
        return new Session(token, r.getResponse().getCookies());
    }

    private int refresh(Session s) throws Exception {
        return mvc.perform(post("/api/auth/refresh").header("X-Tenant-Slug", "default").cookie(s.cookies()))
                .andReturn().getResponse().getStatus();
    }

    private int me(Session s) throws Exception {
        return mvc.perform(get("/api/auth/me").header("Authorization", "Bearer " + s.accessToken()))
                .andReturn().getResponse().getStatus();
    }

    private int liveRefreshTokens(User u) {
        Integer n = jdbc.queryForObject(
                "select count(*) from refresh_tokens where user_id = ? and revoked_at is null and used_at is null",
                Integer.class, u.getId());
        return n == null ? 0 : n;
    }

    private void asTenantAdmin() {
        Tenant t = home();
        TenantContext.set(t.getSlug(), t.getId(), AdminRole.SUPER_ADMIN);
    }

    @Test
    @DisplayName("a session works before deactivation (control)")
    void sessionWorksWhileActive() throws Exception {
        Session s = signIn(user());

        assertThat(me(s)).isEqualTo(200);
        assertThat(refresh(s)).isEqualTo(200);
    }

    @Test
    @DisplayName("an inactive account can neither refresh nor use its access token")
    void inactiveAccountIsRefused() throws Exception {
        User u = user();
        Session s = signIn(u);

        // Deactivated by a path that does nothing else -- the state every
        // deactivated user was left in before.
        jdbc.update("update users set active = false where id = ?", u.getId());

        assertThat(refresh(s)).as("refresh after deactivation").isEqualTo(401);
        assertThat(me(s)).as("old access token after deactivation").isEqualTo(401);
    }

    @Test
    @DisplayName("a deleted account's access token is not authenticated")
    void deletedAccountIsRefused() throws Exception {
        User u = user();
        Session s = signIn(u);

        jdbc.update("delete from refresh_tokens where user_id = ?", u.getId());
        jdbc.update("delete from users where id = ?", u.getId());

        assertThat(me(s)).isEqualTo(401);
    }

    @Test
    @DisplayName("SCIM deactivation ends every session, and reactivation does not resume them")
    void scimDeactivationEndsSessions() throws Exception {
        User u = user();
        Session s = signIn(u);
        assertThat(liveRefreshTokens(u)).isPositive();

        asTenantAdmin();
        ScimPatchRequestDto off = new ScimPatchRequestDto();
        ScimPatchRequestDto.Operation op = new ScimPatchRequestDto.Operation();
        op.setOp("replace");
        op.setPath("active");
        op.setValue(false);
        off.setOperations(List.of(op));
        scim.patch(u.getId(), off, "/scim/v2/default/Users/" + u.getId());

        assertThat(liveRefreshTokens(u)).as("refresh families revoked").isZero();
        assertThat(me(s)).isEqualTo(401);

        // Reactivated: the person signs in afresh; the old session stays dead.
        jdbc.update("update users set active = true where id = ?", u.getId());
        assertThat(refresh(s)).as("old refresh cookie after reactivation").isEqualTo(401);
        assertThat(me(s)).as("old access token after reactivation").isEqualTo(401);
    }

    @Test
    @DisplayName("admin delete revokes the refresh families, so a restore does not resume them")
    void adminDeleteEndsSessions() throws Exception {
        User u = user();
        Session s = signIn(u);

        asTenantAdmin();
        admin.deleteUser(u.getId());

        assertThat(liveRefreshTokens(u)).isZero();
        admin.restoreUser(u.getId());
        assertThat(refresh(s)).isEqualTo(401);
        assertThat(me(s)).isEqualTo(401);
    }
}
