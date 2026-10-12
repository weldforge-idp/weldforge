package tech.cwvermaak.weldforge.integration;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.web.servlet.MockMvc;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import tech.cwvermaak.weldforge.model.Tenant;
import tech.cwvermaak.weldforge.repository.TenantRepository;

import com.jayway.jsonpath.JsonPath;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

/**
 * A defect found by the OpenID Foundation conformance suite on 2026-09-20 that
 * no existing test could have caught.
 *
 * <p>The cause is worth naming: <em>nothing in this repo exercised the protocol
 * the way a real relying party does.</em> The unit and BDD suites call services
 * directly, so they never saw an HTTP method at all. The bug lived on the wire,
 * not in the logic, which is exactly the class of thing that reaches production.
 *
 * <p>Its sibling — an empty {@code code_challenge} surviving the consent form —
 * is pinned by {@code OidcAuthorizationControllerBlankParamTest} instead. An
 * earlier draft asserted it here through an unauthenticated POST, which passed
 * with and without the fix: the request never reached code issuance, so the
 * test proved nothing.
 */
@SpringBootTest
@AutoConfigureMockMvc
@Testcontainers
@EnabledIfSystemProperty(named = "tests.integration", matches = "true")
@DisplayName("Regressions found by the OIDC conformance suite")
class OidcConformanceRegressionIntegrationTest {

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

    private Tenant newTenant() {
        String slug = "conf-" + UUID.randomUUID().toString().substring(0, 8);
        return tenants.saveAndFlush(Tenant.builder().slug(slug).name(slug).displayName(slug).build());
    }

    /**
     * OIDC Core §5.3.1: the UserInfo Endpoint MUST support GET <em>and</em>
     * POST. Only {@code @GetMapping} was declared, so POST returned 405 and
     * {@code oidcc-userinfo-post-header} failed.
     *
     * <p>Asserting "not 405" rather than a success status is deliberate: with
     * no bearer token the correct answer is 401, and pinning the exact
     * unauthenticated body would test the wrong thing. What matters is that the
     * method is routed at all.
     */
    @Test
    @DisplayName("userinfo accepts POST, not only GET (Core 5.3.1)")
    void userinfo_accepts_post() throws Exception {
        Tenant t = newTenant();
        String path = "/t/" + t.getSlug() + "/oauth2/userinfo";

        int getStatus  = mvc.perform(get(path)).andReturn().getResponse().getStatus();
        int postStatus = mvc.perform(post(path)).andReturn().getResponse().getStatus();

        assertThat(getStatus)
                .as("GET has always worked")
                .isNotEqualTo(405);
        assertThat(postStatus)
                .as("POST returned 405 until 2026-09-20; the spec says MUST support it")
                .isNotEqualTo(405);
        assertThat(postStatus)
                .as("both methods are the same code path, so they answer alike")
                .isEqualTo(getStatus);
    }

    /**
     * RFC 8414 3.1 and the Model Context Protocol's discovery rules: for an
     * issuer with a path, a client inserts the well-known segment before the
     * path and only falls back to appending it. It tries
     * oauth-authorization-server inserted, then openid-configuration inserted,
     * then openid-configuration appended, and stops at the first document.
     *
     * <p>Only the appended form existed. The other two answered 200 with the
     * admin portal's HTML in production, because the ingress sends everything
     * outside a short list of prefixes to the SPA -- so a client stopping at
     * the first 200 never reached the real document.
     *
     * <p>This test can only prove the application side. The ingress route is in
     * the infrastructure repository and no test here can see it.
     */
    @Test
    @DisplayName("discovery answers at all three URLs a client builds, with one issuer")
    void discovery_at_every_well_known_url() throws Exception {
        Tenant t = newTenant();
        List<String> urls = List.of(
                "/.well-known/oauth-authorization-server/t/" + t.getSlug(),
                "/.well-known/openid-configuration/t/" + t.getSlug(),
                "/t/" + t.getSlug() + "/.well-known/openid-configuration");

        List<String> issuers = new ArrayList<>();
        for (String url : urls) {
            MockHttpServletResponse res = mvc.perform(get(url)).andReturn().getResponse();
            assertThat(res.getStatus()).as("%s must serve the document", url).isEqualTo(200);
            assertThat(res.getContentType())
                    .as("%s must be JSON -- an HTML 200 here is the production defect", url)
                    .startsWith("application/json");
            issuers.add(JsonPath.read(res.getContentAsString(), "$.issuer"));
        }

        // RFC 8414 3.3: a client MUST reject a document whose issuer differs
        // from the one it used to build the URL. Drift between these three
        // would not degrade, it would fail.
        assertThat(issuers).as("one issuer, byte-identical, from all three URLs")
                .containsExactly(issuers.get(0), issuers.get(0), issuers.get(0));
        assertThat(issuers.get(0)).endsWith("/t/" + t.getSlug());
    }

    /** An unknown tenant must not be answered with a document at the new URLs either. */
    @Test
    @DisplayName("the inserted-path URLs 404 for a tenant that does not exist")
    void inserted_path_unknown_tenant_is_not_found() throws Exception {
        assertThat(mvc.perform(get("/.well-known/oauth-authorization-server/t/no-such-tenant"))
                .andReturn().getResponse().getStatus()).isEqualTo(404);
        assertThat(mvc.perform(get("/.well-known/openid-configuration/t/no-such-tenant"))
                .andReturn().getResponse().getStatus()).isEqualTo(404);
    }

}
