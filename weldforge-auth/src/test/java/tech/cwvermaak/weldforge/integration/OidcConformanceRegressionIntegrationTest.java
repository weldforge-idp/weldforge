package tech.cwvermaak.weldforge.integration;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
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

}
