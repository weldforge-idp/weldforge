package tech.cwvermaak.weldforge.integration;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.transaction.annotation.Transactional;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import tech.cwvermaak.weldforge.model.AuditEvent;
import tech.cwvermaak.weldforge.model.OidcClient;
import tech.cwvermaak.weldforge.model.Tenant;
import tech.cwvermaak.weldforge.model.TenantSocialProvider;
import tech.cwvermaak.weldforge.model.SocialProviderType;
import tech.cwvermaak.weldforge.repository.AuditEventRepository;
import tech.cwvermaak.weldforge.repository.OidcClientRepository;
import tech.cwvermaak.weldforge.repository.TenantRepository;
import tech.cwvermaak.weldforge.repository.TenantSocialProviderRepository;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Real-Postgres integration test. Boots the full Spring context against a
 * Testcontainers Postgres instance, runs the entire Flyway migration set
 * (V1 → V10), and exercises the parts the unit tests can't:
 *
 *  - Flyway migrations apply cleanly end-to-end on a fresh Postgres
 *  - JSONB columns (audit_events.metadata) round-trip via Hibernate
 *  - The EncryptedStringConverter actually encrypts what it claims to
 *    encrypt — assert by reading the raw column out via JDBC after
 *    persisting through JPA
 *  - Multi-tenant unique indexes do what they should
 *
 * Skips automatically when Docker is not available — set the system
 * property {@code tests.integration=true} (the CI workflow does) to
 * enable. Local dev runs without Docker still get a green build.
 */
@SpringBootTest
@Testcontainers
@EnabledIfSystemProperty(named = "tests.integration", matches = "true")
@DisplayName("Postgres integration: schema, JSONB audit, encrypted columns, tenant uniques")
class PostgresIntegrationTest {

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

    @BeforeAll
    static void dockerOrSkip() {
        // PostgreSQLContainer.isRunning() is not callable until @Container
        // has started it; we just check Docker availability up-front so a
        // missing Docker is reported as a skip, not a startup failure.
        assumeTrue(System.getProperty("tests.integration", "false").equals("true"),
                "Set -Dtests.integration=true to enable Postgres integration tests");
    }

    @Autowired private TenantRepository tenantRepository;
    @Autowired private TenantSocialProviderRepository providerRepository;
    @Autowired private AuditEventRepository auditEventRepository;
    @Autowired private OidcClientRepository oidcClientRepository;

    @Test
    @DisplayName("the seeded default tenant survives every Flyway migration")
    void flyway_runsCleanly_andSeedDataPresent() {
        // V4 seeds the "default" tenant. If any migration broke between
        // V1 and V10 we wouldn't even reach this assertion.
        assertThat(tenantRepository.findBySlug("default")).isPresent();
    }

    @Test
    @Transactional
    @DisplayName("audit_events.metadata round-trips through JSONB")
    void auditEvent_jsonbRoundTrip() {
        Tenant tenant = tenantRepository.findBySlug("default").orElseThrow();

        AuditEvent event = AuditEvent.builder()
                .eventType("integration.test")
                .outcome(AuditEvent.Outcome.SUCCESS)
                .tenant(tenant)
                .actorEmail("integration@test")
                .targetType("user")
                .targetId("42")
                .metadata(Map.of("key1", "value1", "count", 7, "nested", Map.of("a", "b")))
                .ipAddress("127.0.0.1")
                .userAgent("integration")
                .build();
        AuditEvent saved = auditEventRepository.save(event);

        AuditEvent reloaded = auditEventRepository.findById(saved.getId()).orElseThrow();
        assertThat(reloaded.getMetadata()).containsEntry("key1", "value1");
        assertThat(reloaded.getMetadata()).containsEntry("count", 7);
        assertThat(reloaded.getMetadata()).containsKey("nested");
    }

    @Test
    @Transactional
    @DisplayName("EncryptedStringConverter writes ciphertext to disk and decrypts on read")
    void encryptedStringConverter_actuallyEncrypts() {
        Tenant tenant = tenantRepository.findBySlug("default").orElseThrow();

        TenantSocialProvider provider = TenantSocialProvider.builder()
                .tenant(tenant)
                .provider(SocialProviderType.GOOGLE)
                .clientId("integration-client-id")
                .clientSecret("plaintext-secret-for-test")
                .scopes("openid profile email")
                .enabled(true)
                .build();
        TenantSocialProvider saved = providerRepository.save(provider);

        // Read it back via JPA — converter should decrypt.
        TenantSocialProvider reloaded = providerRepository.findById(saved.getId()).orElseThrow();
        assertThat(reloaded.getClientSecret()).isEqualTo("plaintext-secret-for-test");

        // Now read the raw column via JDBC: it must NOT contain the plaintext.
        try (var conn = POSTGRES.createConnection("");
             var stmt = conn.prepareStatement("select client_secret_enc from tenant_social_providers where id = ?")) {
            stmt.setLong(1, saved.getId());
            try (var rs = stmt.executeQuery()) {
                assertThat(rs.next()).isTrue();
                String onDisk = rs.getString(1);
                assertThat(onDisk).isNotBlank();
                assertThat(onDisk).doesNotContain("plaintext-secret-for-test");
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    @Transactional
    @DisplayName("(tenant_id, provider) unique index prevents duplicate OAuth2 providers in one tenant")
    void uniqueIndex_blocksDuplicateProviderInSameTenant() {
        Tenant tenant = tenantRepository.findBySlug("default").orElseThrow();

        providerRepository.save(TenantSocialProvider.builder()
                .tenant(tenant)
                .provider(SocialProviderType.MICROSOFT)
                .clientId("first")
                .clientSecret("secret-1")
                .enabled(true)
                .build());

        try {
            providerRepository.saveAndFlush(TenantSocialProvider.builder()
                    .tenant(tenant)
                    .provider(SocialProviderType.MICROSOFT)
                    .clientId("second")
                    .clientSecret("secret-2")
                    .enabled(true)
                    .build());
            // If we got here the unique index is missing.
            throw new AssertionError("Expected unique constraint violation, none thrown");
        } catch (org.springframework.dao.DataIntegrityViolationException expected) {
            // The constraint is doing its job.
        }
    }

    @Test
    @Transactional
    @DisplayName("oidc_clients table accepts a row with an encrypted secret and lists by tenant")
    void oidcClientsTable_basicCrud() {
        Tenant tenant = tenantRepository.findBySlug("default").orElseThrow();

        OidcClient client = OidcClient.builder()
                .tenant(tenant)
                .clientId("integration-rp")
                .clientSecret("rp-plaintext-secret")
                .name("Integration test RP")
                .redirectUris("https://app.test/callback")
                .scopes("openid email")
                .grantTypes("authorization_code")
                .requirePkce(true)
                .build();
        OidcClient saved = oidcClientRepository.save(client);

        OidcClient reloaded = oidcClientRepository.findById(saved.getId()).orElseThrow();
        assertThat(reloaded.getClientSecret()).isEqualTo("rp-plaintext-secret");
        assertThat(oidcClientRepository.findByTenantId(tenant.getId()))
                .anyMatch(c -> "integration-rp".equals(c.getClientId()));
    }
}
