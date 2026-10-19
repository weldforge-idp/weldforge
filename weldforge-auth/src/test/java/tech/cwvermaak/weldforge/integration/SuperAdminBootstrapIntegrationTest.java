package tech.cwvermaak.weldforge.integration;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import tech.cwvermaak.weldforge.config.SuperAdminBootstrap;
import tech.cwvermaak.weldforge.model.AdminRole;
import tech.cwvermaak.weldforge.model.AuthProvider;
import tech.cwvermaak.weldforge.model.Tenant;
import tech.cwvermaak.weldforge.model.User;
import tech.cwvermaak.weldforge.repository.AdminMembershipRepository;
import tech.cwvermaak.weldforge.repository.TenantRepository;
import tech.cwvermaak.weldforge.repository.UserRepository;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

/**
 * The bootstrap promotion against a real database, where the user's tenant is
 * a lazy proxy.
 *
 * <p>Production, 2026-10-19: the bootstrap user was found un-promoted, the
 * promotion was saved, and the log line after it read the tenant's slug from a
 * detached user. LazyInitializationException failed startup, the global
 * membership was never granted, and the identity provider was down until the
 * restart found the user already promoted. The unit test cannot see this: its
 * tenant is a plain object.
 */
@SpringBootTest
@Testcontainers
@EnabledIfSystemProperty(named = "tests.integration", matches = "true")
@DisplayName("Bootstrap super-admin promotion on a real database")
class SuperAdminBootstrapIntegrationTest {

    private static final String EMAIL = "bootstrap-admin@test.example";

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
        // No such user at startup, so the startup run only warns; the test
        // creates the user and runs the bootstrap itself.
        registry.add("app.admin.bootstrap-super-admin-email", () -> EMAIL);
    }

    @Autowired SuperAdminBootstrap bootstrap;
    @Autowired TenantRepository tenants;
    @Autowired UserRepository users;
    @Autowired AdminMembershipRepository memberships;

    @Test
    @DisplayName("promotes the user and grants the global membership without failing startup")
    void promotesWithLazyTenant() {
        Tenant tenant = tenants.saveAndFlush(Tenant.builder()
                .slug("bootstrap-it").name("bootstrap-it").displayName("bootstrap-it").build());
        User saved = users.saveAndFlush(User.builder()
                .tenant(tenant)
                .username(EMAIL)
                .email(EMAIL)
                .provider(AuthProvider.LOCAL)
                .providerId(EMAIL)
                .adminRole(AdminRole.NONE)
                .build());

        assertThatCode(() -> bootstrap.run(null)).doesNotThrowAnyException();

        User promoted = users.findById(saved.getId()).orElseThrow();
        assertThat(promoted.getAdminRole()).isEqualTo(AdminRole.SUPER_ADMIN);
        assertThat(promoted.isSuperAdmin()).isTrue();
        assertThat(memberships.findByUser_Id(saved.getId()))
                .anyMatch(m -> m.getTenant() == null && m.getAdminRole() == AdminRole.SUPER_ADMIN);
    }
}
