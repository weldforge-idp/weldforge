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
import tech.cwvermaak.weldforge.model.Tenant;
import tech.cwvermaak.weldforge.repository.TenantRepository;
import tech.cwvermaak.weldforge.service.security.EffectivePasswordPolicy;
import tech.cwvermaak.weldforge.service.security.PasswordPolicyService;

import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * V60: the {@code tenants.password_policy} JSONB column, end to end.
 *
 * <p>The unit tests cover the merge arithmetic against hand-built maps. What
 * they cannot show is that a map survives a round trip through Postgres as the
 * same thing — JSONB deserialises integers as {@code Integer}, but that is a
 * property of the driver and mapping, not of our code, and it is exactly the
 * kind of assumption that breaks quietly on an upgrade. A stored policy that
 * came back with {@code minLength} as a {@code Double} would fall back to the
 * baseline on every login and nothing would say so.
 */
@SpringBootTest
@Testcontainers
@EnabledIfSystemProperty(named = "tests.integration", matches = "true")
@DisplayName("Per-tenant password policy survives the database")
class TenantPasswordPolicyIntegrationTest {

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

    @Autowired TenantRepository tenants;
    @Autowired PasswordPolicyService passwordPolicyService;

    private Tenant newTenant(Map<String, Object> policy) {
        String slug = "pol-" + UUID.randomUUID().toString().substring(0, 8);
        return tenants.saveAndFlush(Tenant.builder()
                .slug(slug).name(slug).displayName(slug)
                .passwordPolicy(policy)
                .build());
    }

    @Test
    @DisplayName("a policy round-trips, and its numbers come back as numbers")
    void policy_round_trips() {
        Tenant saved = newTenant(Map.of(
                "minLength", 16,
                "requireDigit", true));

        Tenant reloaded = tenants.findById(saved.getId()).orElseThrow();

        assertThat(reloaded.getPasswordPolicy())
                .containsEntry("minLength", 16)
                .containsEntry("requireDigit", true);

        // The value that matters: resolution must actually read it back, not
        // silently fall through to the baseline because the type changed.
        EffectivePasswordPolicy p = passwordPolicyService.effectivePolicyFor(reloaded);
        assertThat(p.minLength()).isEqualTo(16);
        assertThat(p.requireDigit()).isTrue();
    }

    @Test
    @DisplayName("a partial policy inherits every key it does not mention")
    void partial_policy_inherits_the_rest() {
        Tenant saved = newTenant(Map.of("minLength", 20));
        Tenant reloaded = tenants.findById(saved.getId()).orElseThrow();

        EffectivePasswordPolicy tenantPolicy = passwordPolicyService.effectivePolicyFor(reloaded);
        EffectivePasswordPolicy baseline = passwordPolicyService.baseline();

        assertThat(tenantPolicy.minLength()).isEqualTo(20);
        assertThat(tenantPolicy.maxLength()).isEqualTo(baseline.maxLength());
        assertThat(tenantPolicy.requireUppercase()).isEqualTo(baseline.requireUppercase());
        assertThat(tenantPolicy.requireLowercase()).isEqualTo(baseline.requireLowercase());
        assertThat(tenantPolicy.requireDigit()).isEqualTo(baseline.requireDigit());
        assertThat(tenantPolicy.requireSymbol()).isEqualTo(baseline.requireSymbol());
    }

    @Test
    @DisplayName("NULL is the default, and behaves exactly as the deployment baseline")
    void null_policy_is_the_baseline() {
        Tenant saved = newTenant(null);
        Tenant reloaded = tenants.findById(saved.getId()).orElseThrow();

        assertThat(reloaded.getPasswordPolicy())
                .as("V60 adds no default, so every existing tenant reads NULL")
                .isNull();
        assertThat(passwordPolicyService.effectivePolicyFor(reloaded))
                .isEqualTo(passwordPolicyService.baseline());
    }

    @Test
    @DisplayName("a stored policy weaker than the baseline is kept but has no effect")
    void weaker_policy_is_stored_and_ignored() {
        // Stored rather than rejected on purpose: the baseline may later relax,
        // at which point this value starts to apply. Refusing it at write time
        // would make the policy depend on the order two settings were edited.
        Tenant saved = newTenant(Map.of("minLength", 4));
        Tenant reloaded = tenants.findById(saved.getId()).orElseThrow();

        assertThat(reloaded.getPasswordPolicy()).containsEntry("minLength", 4);
        assertThat(passwordPolicyService.effectivePolicyFor(reloaded).minLength())
                .as("the baseline still wins — overrides may only tighten")
                .isEqualTo(passwordPolicyService.baseline().minLength());
    }
}
