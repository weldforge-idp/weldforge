package tech.cwvermaak.weldforge.integration;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import tech.cwvermaak.weldforge.model.AdminRole;
import tech.cwvermaak.weldforge.model.AuditEvent;
import tech.cwvermaak.weldforge.model.AuthProvider;
import tech.cwvermaak.weldforge.model.Tenant;
import tech.cwvermaak.weldforge.model.User;
import tech.cwvermaak.weldforge.repository.AuditEventRepository;
import tech.cwvermaak.weldforge.repository.TenantRepository;
import tech.cwvermaak.weldforge.repository.UserRepository;
import tech.cwvermaak.weldforge.service.JwtService;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;

/**
 * The audit page against a real Postgres. Every search without an actor
 * filter -- the page's default load -- answered 500: the JPQL bound the absent
 * filter as a null inside {@code concat()}, the driver typed it bytea, and
 * {@code lower(bytea)} does not exist. Mocked-repository tests cannot see it.
 */
@SpringBootTest
@AutoConfigureMockMvc
@Testcontainers
@EnabledIfSystemProperty(named = "tests.integration", matches = "true")
@DisplayName("Audit search on a real database")
class AuditSearchIntegrationTest {

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
    @Autowired AuditEventRepository events;
    @Autowired JwtService jwtService;
    @Autowired ObjectMapper json;

    private Tenant home() {
        return tenants.findBySlug("default").orElseThrow();
    }

    private User admin() {
        String tag = UUID.randomUUID().toString().substring(0, 8);
        return users.save(User.builder()
                .tenant(home())
                .username("audit-admin-" + tag)
                .email("audit-admin-" + tag + "@test.example")
                .provider(AuthProvider.LOCAL)
                .providerId("audit-admin-" + tag)
                .active(true)
                .adminRole(AdminRole.TENANT_ADMIN)
                .build());
    }

    private void event(Tenant t, String actorEmail, String type) {
        events.save(AuditEvent.builder()
                .tenant(t)
                .actorEmail(actorEmail)
                .eventType(type)
                .outcome(AuditEvent.Outcome.SUCCESS)
                .build());
    }

    private MvcResult search(User caller, MockHttpServletRequestBuilder req) throws Exception {
        String token = jwtService.generateAccessToken(caller.getEmail(), caller.getTenant().getId(),
                caller.getTenant().getSlug(), false, caller.getTokenVersion(), null, null,
                caller.getAdminRole().name(), "https://sso.weldforge.org/t/" + caller.getTenant().getSlug(),
                List.of("pwd"), null);
        return mvc.perform(req.header("Authorization", "Bearer " + token)).andReturn();
    }

    private List<String> actors(MvcResult r) throws Exception {
        JsonNode body = json.readTree(r.getResponse().getContentAsString());
        List<String> out = new ArrayList<>();
        body.get("content").forEach(n -> out.add(n.path("actorEmail").asText()));
        return out;
    }

    @Test
    @DisplayName("no filters (the page's default load) answers 200, newest first")
    void unfilteredSearchWorks() throws Exception {
        User admin = admin();
        String tag = UUID.randomUUID().toString().substring(0, 6);
        event(home(), "first-" + tag + "@test.example", "test.event");
        event(home(), "second-" + tag + "@test.example", "test.event");

        MvcResult r = search(admin, get("/api/admin/audit"));

        assertThat(r.getResponse().getStatus()).isEqualTo(200);
        List<String> actors = actors(r);
        assertThat(actors.indexOf("second-" + tag + "@test.example"))
                .isLessThan(actors.indexOf("first-" + tag + "@test.example"));
    }

    @Test
    @DisplayName("the CSV export, which has the same default, answers 200")
    void unfilteredExportWorks() throws Exception {
        MvcResult r = search(admin(), get("/api/admin/audit/export.csv"));

        assertThat(r.getResponse().getStatus()).isEqualTo(200);
        assertThat(r.getResponse().getContentAsString()).startsWith("id,created_at,");
    }

    @Test
    @DisplayName("each filter on its own works")
    void eachFilterWorks() throws Exception {
        User admin = admin();
        String tag = UUID.randomUUID().toString().substring(0, 6);
        event(home(), "Mixed.Case-" + tag + "@test.example", "type-" + tag);

        assertThat(search(admin, get("/api/admin/audit").param("eventType", "type-" + tag))
                .getResponse().getStatus()).isEqualTo(200);
        assertThat(actors(search(admin, get("/api/admin/audit").param("actorEmail", "mixed.case-" + tag))))
                .as("actor filter is case-insensitive and partial")
                .containsExactly("Mixed.Case-" + tag + "@test.example");
        assertThat(search(admin, get("/api/admin/audit").param("since", "2020-01-01T00:00:00"))
                .getResponse().getStatus()).isEqualTo(200);
        assertThat(search(admin, get("/api/admin/audit").param("until", "2100-01-01T00:00:00"))
                .getResponse().getStatus()).isEqualTo(200);
    }

    @Test
    @DisplayName("LIKE wildcards in the actor filter are matched literally")
    void wildcardsAreLiteral() throws Exception {
        User admin = admin();
        String tag = UUID.randomUUID().toString().substring(0, 6);
        event(home(), "axb-" + tag + "@test.example", "test.event");

        assertThat(actors(search(admin, get("/api/admin/audit").param("actorEmail", "a_b-" + tag)))).isEmpty();
        assertThat(actors(search(admin, get("/api/admin/audit").param("actorEmail", "%" + tag)))).isEmpty();
    }

    @Test
    @DisplayName("a tenant admin sees only their own tenant's events")
    void scopedToCallersTenant() throws Exception {
        User admin = admin();
        String tag = UUID.randomUUID().toString().substring(0, 6);
        Tenant other = tenants.save(Tenant.builder().slug("audit-" + tag).name("o").displayName("o").build());
        event(other, "elsewhere-" + tag + "@test.example", "test.event");

        // Even asking for the other tenant by id is ignored for a non-super-admin.
        MvcResult r = search(admin, get("/api/admin/audit").param("tenantId", String.valueOf(other.getId())));

        assertThat(r.getResponse().getStatus()).isEqualTo(200);
        assertThat(actors(r)).doesNotContain("elsewhere-" + tag + "@test.example");
    }
}
