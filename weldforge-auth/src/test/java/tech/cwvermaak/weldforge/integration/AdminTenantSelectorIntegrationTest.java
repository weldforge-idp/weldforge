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
import tech.cwvermaak.weldforge.model.AdminMembership;
import tech.cwvermaak.weldforge.model.AdminRole;
import tech.cwvermaak.weldforge.model.AuthProvider;
import tech.cwvermaak.weldforge.model.Tenant;
import tech.cwvermaak.weldforge.model.User;
import tech.cwvermaak.weldforge.repository.AdminMembershipRepository;
import tech.cwvermaak.weldforge.repository.OidcClientRepository;
import tech.cwvermaak.weldforge.repository.TenantRepository;
import tech.cwvermaak.weldforge.repository.UserRepository;
import tech.cwvermaak.weldforge.service.JwtService;

import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

/**
 * The 2026-09-11 incident, through the real filter chain: an admin write that
 * names another tenant must land there or be refused -- never succeed quietly
 * in the caller's home tenant.
 */
@SpringBootTest
@AutoConfigureMockMvc
@Testcontainers
@EnabledIfSystemProperty(named = "tests.integration", matches = "true")
@DisplayName("Admin tenant selector: land in the named tenant or refuse")
class AdminTenantSelectorIntegrationTest {

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
    @Autowired TenantRepository tenants;
    @Autowired UserRepository users;
    @Autowired AdminMembershipRepository memberships;
    @Autowired OidcClientRepository clients;
    @Autowired JwtService jwtService;

    private Tenant homeTenant() {
        return tenants.findBySlug("default").orElseThrow();
    }

    private Tenant newTenant() {
        String slug = "tgt-" + UUID.randomUUID().toString().substring(0, 8);
        return tenants.save(Tenant.builder().slug(slug).name(slug).displayName(slug).build());
    }

    private User admin(boolean superAdminFlag, AdminRole role) {
        String tag = UUID.randomUUID().toString().substring(0, 8);
        return users.save(User.builder()
                .tenant(homeTenant())
                .username("admin-" + tag)
                .email("admin-" + tag + "@test.example")
                .provider(AuthProvider.LOCAL)
                .providerId("admin-" + tag)
                .active(true)
                .superAdmin(superAdminFlag)
                .adminRole(role)
                .build());
    }

    private String tokenFor(User u) {
        return jwtService.generateAccessToken(u.getEmail(), u.getTenant().getId(), u.getTenant().getSlug(),
                u.isSuperAdmin(), u.getTokenVersion(), null, null, u.getAdminRole().name(),
                "https://sso.weldforge.org/t/" + u.getTenant().getSlug(), List.of("pwd"), null);
    }

    private static String clientBody(String clientId) {
        return "{\"clientId\":\"" + clientId + "\",\"name\":\"KeyCrypt\","
                + "\"redirectUris\":[\"https://keycrypt.test/login/oauth2/code/weldforge\"],"
                + "\"scopes\":[\"openid\",\"profile\",\"email\"],\"grantTypes\":[\"authorization_code\"]}";
    }

    private MvcResult createClient(User caller, String header, String tenantSlug, String clientId) throws Exception {
        return mvc.perform(post("/api/admin/oidc/clients")
                        .header("Authorization", "Bearer " + tokenFor(caller))
                        .header(header, tenantSlug)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(clientBody(clientId)))
                .andReturn();
    }

    private int authorizeStatus(String tenantSlug, String clientId) throws Exception {
        return mvc.perform(get("/t/" + tenantSlug + "/oauth2/authorize")
                        .param("response_type", "code")
                        .param("client_id", clientId)
                        .param("redirect_uri", "https://keycrypt.test/login/oauth2/code/weldforge")
                        .param("scope", "openid")
                        .param("code_challenge", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM")
                        .param("code_challenge_method", "S256"))
                .andReturn().getResponse().getStatus();
    }

    private boolean existsIn(Tenant t, String clientId) {
        return clients.findByTenantIdAndClientId(t.getId(), clientId).isPresent();
    }

    // ---- refused, never misdirected --------------------------------------

    @Test
    @DisplayName("adm=SUPER_ADMIN, sa=false, no membership + X-Tenant-Slug: 403, and nothing lands at home")
    void unentitled_legacy_selector_is_refused() throws Exception {
        User caller = admin(false, AdminRole.SUPER_ADMIN);
        Tenant target = newTenant();
        String clientId = "kc-" + UUID.randomUUID().toString().substring(0, 8);

        MvcResult r = createClient(caller, "X-Tenant-Slug", target.getSlug(), clientId);

        assertThat(r.getResponse().getStatus()).isEqualTo(403);
        assertThat(r.getResponse().getContentAsString()).contains("tenant_access_denied");
        assertThat(existsIn(homeTenant(), clientId)).as("no silent write to the home tenant").isFalse();
        assertThat(existsIn(target, clientId)).isFalse();
    }

    @Test
    @DisplayName("adm=SUPER_ADMIN, sa=false, no membership + X-WF-Tenant: 403 as well")
    void unentitled_selector_is_refused() throws Exception {
        User caller = admin(false, AdminRole.SUPER_ADMIN);
        Tenant target = newTenant();
        String clientId = "kc-" + UUID.randomUUID().toString().substring(0, 8);

        MvcResult r = createClient(caller, "X-WF-Tenant", target.getSlug(), clientId);

        assertThat(r.getResponse().getStatus()).isEqualTo(403);
        assertThat(existsIn(homeTenant(), clientId)).isFalse();
    }

    @Test
    @DisplayName("sa=true with no global membership is refused too -- one rule, memberships")
    void sa_flag_alone_no_longer_switches() throws Exception {
        // Before this fix the `sa` claim alone switched tenant, bypassing the
        // membership rule and the audit trail.
        User caller = admin(true, AdminRole.SUPER_ADMIN);
        Tenant target = newTenant();
        String clientId = "kc-" + UUID.randomUUID().toString().substring(0, 8);

        MvcResult r = createClient(caller, "X-Tenant-Slug", target.getSlug(), clientId);

        assertThat(r.getResponse().getStatus()).isEqualTo(403);
        assertThat(existsIn(homeTenant(), clientId)).isFalse();
    }

    @Test
    @DisplayName("An unknown tenant is a 404, not a quiet write at home")
    void unknown_tenant_is_404() throws Exception {
        User caller = admin(true, AdminRole.SUPER_ADMIN);
        memberships.save(AdminMembership.builder().user(caller).tenant(null).adminRole(AdminRole.SUPER_ADMIN).build());
        String clientId = "kc-" + UUID.randomUUID().toString().substring(0, 8);

        MvcResult r = createClient(caller, "X-Tenant-Slug", "no-such-tenant", clientId);

        assertThat(r.getResponse().getStatus()).isEqualTo(404);
        assertThat(existsIn(homeTenant(), clientId)).isFalse();
    }

    // ---- entitled, and it lands where it was sent ---------------------------

    @Test
    @DisplayName("An entitled super-admin's client lands in the named tenant, and only there")
    void entitled_super_admin_lands_in_target() throws Exception {
        User caller = admin(true, AdminRole.SUPER_ADMIN);
        memberships.save(AdminMembership.builder().user(caller).tenant(null).adminRole(AdminRole.SUPER_ADMIN).build());
        Tenant target = newTenant();
        String clientId = "kc-" + UUID.randomUUID().toString().substring(0, 8);

        MvcResult r = createClient(caller, "X-WF-Tenant", target.getSlug(), clientId);

        assertThat(r.getResponse().getStatus()).isEqualTo(200);
        assertThat(r.getResponse().getHeader("X-WF-Acting-Tenant")).isEqualTo(target.getSlug());
        assertThat(existsIn(target, clientId)).isTrue();
        assertThat(existsIn(homeTenant(), clientId)).isFalse();
        // The protocol surface agrees: the target knows the client (302 to its
        // login), the home tenant does not (400 invalid_client).
        assertThat(authorizeStatus(target.getSlug(), clientId)).isEqualTo(302);
        assertThat(authorizeStatus("default", clientId)).isEqualTo(400);
    }

    @Test
    @DisplayName("The legacy header, from an entitled super-admin, lands in the named tenant too")
    void entitled_legacy_selector_lands_in_target() throws Exception {
        User caller = admin(true, AdminRole.SUPER_ADMIN);
        memberships.save(AdminMembership.builder().user(caller).tenant(null).adminRole(AdminRole.SUPER_ADMIN).build());
        Tenant target = newTenant();
        String clientId = "kc-" + UUID.randomUUID().toString().substring(0, 8);

        MvcResult r = createClient(caller, "X-Tenant-Slug", target.getSlug(), clientId);

        assertThat(r.getResponse().getStatus()).isEqualTo(200);
        assertThat(existsIn(target, clientId)).isTrue();
        assertThat(existsIn(homeTenant(), clientId)).isFalse();
    }

    // ---- one definition: the role that shows the picker is the role that works --

    @Test
    @DisplayName("Promoting to SUPER_ADMIN grants the cross-tenant reach; demoting takes it away")
    void admin_role_change_moves_cross_tenant_reach() throws Exception {
        User granter = admin(true, AdminRole.SUPER_ADMIN);
        memberships.save(AdminMembership.builder().user(granter).tenant(null).adminRole(AdminRole.SUPER_ADMIN).build());
        User promoted = admin(false, AdminRole.NONE);
        Tenant target = newTenant();

        assertThat(setRole(granter, promoted, "SUPER_ADMIN")).isEqualTo(200);
        promoted = reload(promoted);
        // The portal shows the picker to this token (adm=SUPER_ADMIN) ...
        assertThat(promoted.getAdminRole()).isEqualTo(AdminRole.SUPER_ADMIN);
        // ... and the backend honours it.
        String first = "kc-" + UUID.randomUUID().toString().substring(0, 8);
        assertThat(createClient(promoted, "X-WF-Tenant", target.getSlug(), first).getResponse().getStatus())
                .isEqualTo(200);
        assertThat(existsIn(target, first)).isTrue();

        assertThat(setRole(granter, promoted, "TENANT_ADMIN")).isEqualTo(200);
        promoted = reload(promoted);
        String second = "kc-" + UUID.randomUUID().toString().substring(0, 8);
        assertThat(createClient(promoted, "X-WF-Tenant", target.getSlug(), second).getResponse().getStatus())
                .isEqualTo(403);
        assertThat(existsIn(target, second)).isFalse();
        assertThat(existsIn(homeTenant(), second)).isFalse();
    }

    /** Re-read the role and token version the call changed; the tenant is lazy, so re-attach it. */
    private User reload(User u) {
        User fresh = users.findById(u.getId()).orElseThrow();
        fresh.setTenant(homeTenant());
        return fresh;
    }

    private int setRole(User caller, User target, String role) throws Exception {
        return mvc.perform(post("/api/admin/users/" + target.getId() + "/admin-role")
                        .header("Authorization", "Bearer " + tokenFor(caller))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"adminRole\":\"" + role + "\"}"))
                .andReturn().getResponse().getStatus();
    }

    @Test
    @DisplayName("Without a selector an admin call acts in the home tenant, and says so")
    void no_selector_acts_at_home_and_says_so() throws Exception {
        User caller = admin(true, AdminRole.SUPER_ADMIN);

        MvcResult r = mvc.perform(get("/api/admin/oidc/clients")
                        .header("Authorization", "Bearer " + tokenFor(caller)))
                .andReturn();

        assertThat(r.getResponse().getStatus()).isEqualTo(200);
        assertThat(r.getResponse().getHeader("X-WF-Acting-Tenant")).isEqualTo("default");
    }
}
