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
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import tech.cwvermaak.weldforge.model.AdminRole;
import tech.cwvermaak.weldforge.model.AuthProvider;
import tech.cwvermaak.weldforge.model.Role;
import tech.cwvermaak.weldforge.model.Tenant;
import tech.cwvermaak.weldforge.model.User;
import tech.cwvermaak.weldforge.repository.RoleRepository;
import tech.cwvermaak.weldforge.repository.TenantRepository;
import tech.cwvermaak.weldforge.repository.UserRepository;
import tech.cwvermaak.weldforge.service.JwtService;

import java.net.URI;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;

/**
 * Security review 2026-11-15: {@code /api/admin/**} required only an
 * authenticated caller, and every signed-in end user is one. Several admin
 * service methods never checked the caller's admin role, so an ordinary user
 * could read the audit log and app clients, and rename a role they held to an
 * application's admin role -- which then appeared in their next token.
 * Production answered {@code GET /api/admin/roles} with 200 to an
 * {@code adm=NONE} token.
 */
@SpringBootTest
@AutoConfigureMockMvc
@Testcontainers
@EnabledIfSystemProperty(named = "tests.integration", matches = "true")
@DisplayName("Admin API requires an admin role, not merely a signed-in caller")
class AdminAreaGateIntegrationTest {

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

    @Autowired MockMvc mvc;
    @Autowired TenantRepository tenants;
    @Autowired UserRepository users;
    @Autowired RoleRepository roles;
    @Autowired JwtService jwtService;

    private Tenant home() {
        return tenants.findBySlug("default").orElseThrow();
    }

    private User user(AdminRole role, boolean superAdmin) {
        String tag = UUID.randomUUID().toString().substring(0, 8);
        return users.save(User.builder()
                .tenant(home())
                .username("u-" + tag)
                .email("u-" + tag + "@test.example")
                .provider(AuthProvider.LOCAL)
                .providerId("u-" + tag)
                .active(true)
                .superAdmin(superAdmin)
                .adminRole(role)
                .build());
    }

    private String tokenFor(User u) {
        return jwtService.generateAccessToken(u.getEmail(), u.getTenant().getId(), u.getTenant().getSlug(),
                u.isSuperAdmin(), u.getTokenVersion(), null, null, u.getAdminRole().name(),
                "https://sso.weldforge.org/t/" + u.getTenant().getSlug(), List.of("pwd"), null);
    }

    private Role role(String name) {
        return roles.save(Role.builder().tenant(home()).name(name).build());
    }

    private MvcResult as(User caller, MockHttpServletRequestBuilder req) throws Exception {
        return mvc.perform(req.header("Authorization", "Bearer " + tokenFor(caller))).andReturn();
    }

    private static MockHttpServletRequestBuilder json(MockHttpServletRequestBuilder req, String body) {
        return req.contentType(MediaType.APPLICATION_JSON).content(body);
    }

    // ---- an ordinary signed-in user ------------------------------------------

    @Test
    @DisplayName("an end user (adm=NONE) is refused on admin reads that had no role check")
    void endUserRefusedOnReads() throws Exception {
        User endUser = user(AdminRole.NONE, false);

        for (String path : List.of("/api/admin/roles", "/api/admin/app-clients",
                "/api/admin/environments", "/api/admin/audit")) {
            MvcResult r = as(endUser, get(path));
            assertThat(r.getResponse().getStatus()).as(path).isEqualTo(403);
            assertThat(r.getResponse().getContentAsString()).as(path).contains("admin_role_required");
        }
    }

    @Test
    @DisplayName("an end user cannot rename a role they hold into an application's admin role")
    void endUserCannotRenameRole() throws Exception {
        User endUser = user(AdminRole.NONE, false);
        Role member = role("app:member-" + UUID.randomUUID().toString().substring(0, 6));

        MvcResult r = as(endUser, json(put("/api/admin/roles/" + member.getId()), "{\"name\":\"app:admin\"}"));

        assertThat(r.getResponse().getStatus()).isEqualTo(403);
        assertThat(roles.findById(member.getId()).orElseThrow().getName()).isEqualTo(member.getName());
    }

    @Test
    @DisplayName("a percent-encoded admin path does not get past the gate")
    void encodedPathIsStillGated() throws Exception {
        User endUser = user(AdminRole.NONE, false);

        MvcResult r = as(endUser, get(URI.create("/api/%61dmin/roles")));

        assertThat(r.getResponse().getStatus()).isNotEqualTo(200);
    }

    @Test
    @DisplayName("the role-grant path is left to its own service-account check")
    void roleGrantPathIsExempt() throws Exception {
        User endUser = user(AdminRole.NONE, false);

        MvcResult r = as(endUser, get("/api/admin/users/" + endUser.getId() + "/role-grants"));

        // Refused -- but by RoleGrantService, which is the authority on this
        // path, not by the gate.
        assertThat(r.getResponse().getStatus()).isEqualTo(403);
        assertThat(r.getResponse().getContentAsString()).doesNotContain("admin_role_required");
    }

    // ---- READ_ONLY ----------------------------------------------------------

    @Test
    @DisplayName("READ_ONLY can read roles but cannot assign one, not even to itself")
    void readOnlyCannotAssignRoles() throws Exception {
        User readOnly = user(AdminRole.READ_ONLY, false);
        Role adminRole = role("app:admin-" + UUID.randomUUID().toString().substring(0, 6));

        assertThat(as(readOnly, get("/api/admin/roles")).getResponse().getStatus()).isEqualTo(200);

        MvcResult r = as(readOnly, json(put("/api/admin/users/" + readOnly.getId() + "/roles"),
                "{\"roleIds\":[" + adminRole.getId() + "]}"));

        assertThat(r.getResponse().getStatus()).isEqualTo(403);
        assertThat(users.findById(readOnly.getId()).orElseThrow().getRole()).isNull();
    }

    @Test
    @DisplayName("READ_ONLY cannot create, rename or delete roles")
    void readOnlyCannotWriteRoles() throws Exception {
        User readOnly = user(AdminRole.READ_ONLY, false);
        Role existing = role("app:viewer-" + UUID.randomUUID().toString().substring(0, 6));

        assertThat(as(readOnly, json(post("/api/admin/roles"), "{\"name\":\"made-by-readonly\"}"))
                .getResponse().getStatus()).isEqualTo(403);
        assertThat(as(readOnly, json(put("/api/admin/roles/" + existing.getId()), "{\"name\":\"renamed\"}"))
                .getResponse().getStatus()).isEqualTo(403);
        assertThat(roles.findById(existing.getId()).orElseThrow().getName()).isEqualTo(existing.getName());
    }

    // ---- TENANT_ADMIN -------------------------------------------------------

    @Test
    @DisplayName("TENANT_ADMIN still manages roles")
    void tenantAdminStillWorks() throws Exception {
        User tenantAdmin = user(AdminRole.TENANT_ADMIN, false);
        String name = "app:created-" + UUID.randomUUID().toString().substring(0, 6);

        assertThat(as(tenantAdmin, get("/api/admin/roles")).getResponse().getStatus()).isEqualTo(200);
        assertThat(as(tenantAdmin, json(post("/api/admin/roles"), "{\"name\":\"" + name + "\"}"))
                .getResponse().getStatus()).isEqualTo(200);
    }

    @Test
    @DisplayName("TENANT_ADMIN cannot mint a password-reset token for a super admin, but can for a user")
    void tenantAdminCannotResetSuperAdmin() throws Exception {
        User tenantAdmin = user(AdminRole.TENANT_ADMIN, false);
        User superAdmin = user(AdminRole.SUPER_ADMIN, true);
        User ordinary = user(AdminRole.NONE, false);

        MvcResult refused = as(tenantAdmin, post("/api/admin/users/" + superAdmin.getId() + "/issue-password-reset"));
        assertThat(refused.getResponse().getStatus()).isEqualTo(403);
        assertThat(refused.getResponse().getContentAsString()).doesNotContain("resetToken");

        MvcResult allowed = as(tenantAdmin, post("/api/admin/users/" + ordinary.getId() + "/issue-password-reset"));
        assertThat(allowed.getResponse().getStatus()).isEqualTo(200);
        assertThat(allowed.getResponse().getContentAsString()).contains("resetToken");
    }
}
