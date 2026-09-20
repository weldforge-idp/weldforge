package tech.cwvermaak.weldforge.integration;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import tech.cwvermaak.weldforge.model.AuthProvider;
import tech.cwvermaak.weldforge.model.Tenant;
import tech.cwvermaak.weldforge.model.User;
import tech.cwvermaak.weldforge.repository.TenantRepository;
import tech.cwvermaak.weldforge.repository.UserRepository;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.assertThatCode;

/**
 * V59: one account per email per tenant — and deliberately no stricter.
 *
 * <p>The scope of this constraint is the whole point. WeldForge is a
 * multi-tenant identity provider, and one person legitimately holds accounts in
 * several tenants under the same address; `/llms.txt` publishes that as the
 * contract. Production already contains an address registered in two tenants,
 * so a global unique index on email would not merely be wrong in principle —
 * it would fail to apply, and if forced would break a real user.
 *
 * <p>So this asserts both directions. A test that only proved the duplicate is
 * rejected would pass just as happily against a global constraint, which is the
 * mistake it exists to prevent.
 */
@SpringBootTest
@Testcontainers
@EnabledIfSystemProperty(named = "tests.integration", matches = "true")
@DisplayName("Email uniqueness is scoped to the tenant, not global")
class UniqueEmailPerTenantIntegrationTest {

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
    }

    @Autowired UserRepository users;
    @Autowired TenantRepository tenants;
    @Autowired PasswordEncoder passwordEncoder;

    private Tenant newTenant() {
        String slug = "uniq-" + UUID.randomUUID().toString().substring(0, 8);
        return tenants.save(Tenant.builder().slug(slug).name(slug).displayName(slug).build());
    }

    private User user(Tenant t, String email) {
        String tag = UUID.randomUUID().toString().substring(0, 8);
        return User.builder()
                .tenant(t).username("u-" + tag).email(email)
                .password(passwordEncoder.encode("correct horse battery staple"))
                .provider(AuthProvider.LOCAL).providerId("local").active(true)
                .build();
    }

    @Test
    @DisplayName("a second account with the same email in the SAME tenant is refused")
    void duplicate_within_a_tenant_is_refused() {
        Tenant t = newTenant();
        String email = "dup-" + UUID.randomUUID().toString().substring(0, 8) + "@test.example";

        users.saveAndFlush(user(t, email));

        assertThatThrownBy(() -> users.saveAndFlush(user(t, email)))
                .as("the database must refuse it — the application pre-check is a "
                  + "check-then-insert and two concurrent registrations both pass it")
                .isInstanceOf(DataIntegrityViolationException.class);
    }

    @Test
    @DisplayName("case does not create a second account")
    void case_variants_are_the_same_account() {
        Tenant t = newTenant();
        String tag = UUID.randomUUID().toString().substring(0, 8);

        users.saveAndFlush(user(t, "Case-" + tag + "@Test.Example"));

        // Every lookup is case-insensitive, so without lower() in the index these
        // would be two rows the login path treats as one and resolves arbitrarily.
        assertThatThrownBy(() -> users.saveAndFlush(user(t, "case-" + tag + "@test.example")))
                .isInstanceOf(DataIntegrityViolationException.class);
    }

    @Test
    @DisplayName("the SAME email in a DIFFERENT tenant is still allowed")
    void same_email_across_tenants_is_allowed() {
        Tenant a = newTenant();
        Tenant b = newTenant();
        String shared = "shared-" + UUID.randomUUID().toString().substring(0, 8) + "@test.example";

        users.saveAndFlush(user(a, shared));

        // The direction that matters most. Production already has an address in
        // two tenants, and /llms.txt documents it as supported: "The same address
        // may exist in another tenant." A global unique index would break both.
        assertThatCode(() -> users.saveAndFlush(user(b, shared)))
                .as("one person may hold accounts in several tenants under one address")
                .doesNotThrowAnyException();

        assertThat(users.findByTenant_SlugAndEmailIgnoreCase(a.getSlug(), shared)).isPresent();
        assertThat(users.findByTenant_SlugAndEmailIgnoreCase(b.getSlug(), shared)).isPresent();
    }
}
