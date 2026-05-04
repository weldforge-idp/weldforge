package tech.cwvermaak.weldforge.integration;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
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
import tech.cwvermaak.weldforge.config.tenant.TenantContext;
import tech.cwvermaak.weldforge.model.*;
import tech.cwvermaak.weldforge.repository.SamlServiceProviderRepository;
import tech.cwvermaak.weldforge.repository.TenantRepository;
import tech.cwvermaak.weldforge.repository.TenantSigningKeyRepository;
import tech.cwvermaak.weldforge.repository.UserRepository;
import tech.cwvermaak.weldforge.service.oidc.TenantSigningKeyService;
import tech.cwvermaak.weldforge.service.saml.SamlIdpService;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Integration test for the V14 migration (saml_service_providers table)
 * and the SAML IdP service. Boots a full Spring context against a
 * Testcontainers Postgres instance and exercises:
 *
 *  - V14 migration applies cleanly
 *  - SAML SP CRUD via the repository
 *  - Unique constraint on (tenant_id, entity_id)
 *  - IdP metadata generation with a real signing key
 */
@SpringBootTest
@Testcontainers
@EnabledIfSystemProperty(named = "tests.integration", matches = "true")
@DisplayName("SAML IdP integration: V14 migration, SP persistence, metadata generation")
class SamlIdpIntegrationTest {

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
        assumeTrue(System.getProperty("tests.integration", "false").equals("true"),
                "Set -Dtests.integration=true to enable Postgres integration tests");
    }

    @Autowired private TenantRepository tenantRepository;
    @Autowired private SamlServiceProviderRepository spRepository;
    @Autowired private TenantSigningKeyRepository signingKeyRepository;
    @Autowired private TenantSigningKeyService signingKeyService;
    @Autowired private SamlIdpService samlIdpService;
    @Autowired private UserRepository userRepository;

    @BeforeEach
    void setTenantContext() {
        Tenant tenant = tenantRepository.findBySlug("default").orElseThrow();
        TenantContext.set("default", tenant.getId(), true);
    }

    @Test
    @DisplayName("V14 migration creates saml_service_providers table successfully")
    void v14Migration_appliesCleanly() {
        // If we reach this point, Flyway ran V14 without error.
        // Verify we can query the table.
        assertThat(spRepository.findAll()).isNotNull();
    }

    @Test
    @Transactional
    @DisplayName("SAML SP persists and can be retrieved by tenant and entity ID")
    void samlSp_persistsAndRetrievable() {
        Tenant tenant = tenantRepository.findBySlug("default").orElseThrow();

        SamlServiceProvider sp = SamlServiceProvider.builder()
                .tenant(tenant)
                .entityId("https://sp.example.com/metadata")
                .name("Test SP")
                .acsUrl("https://sp.example.com/acs")
                .sloUrl("https://sp.example.com/slo")
                .nameIdFormat("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress")
                .attributeMappings(Map.of("email", "http://schemas.xmlsoap.org/claims/email"))
                .enabled(true)
                .build();
        SamlServiceProvider saved = spRepository.save(sp);

        assertThat(saved.getId()).isNotNull();
        assertThat(saved.getCreatedAt()).isNotNull();
        assertThat(saved.getUpdatedAt()).isNotNull();

        SamlServiceProvider reloaded = spRepository.findByTenantIdAndEntityId(
                tenant.getId(), "https://sp.example.com/metadata").orElseThrow();
        assertThat(reloaded.getName()).isEqualTo("Test SP");
        assertThat(reloaded.getAcsUrl()).isEqualTo("https://sp.example.com/acs");
        assertThat(reloaded.getAttributeMappings())
                .containsEntry("email", "http://schemas.xmlsoap.org/claims/email");
    }

    @Test
    @Transactional
    @DisplayName("unique constraint on (tenant_id, entity_id) prevents duplicate SPs")
    void uniqueConstraint_blocksDuplicateEntityIdInSameTenant() {
        Tenant tenant = tenantRepository.findBySlug("default").orElseThrow();

        spRepository.save(SamlServiceProvider.builder()
                .tenant(tenant)
                .entityId("https://duplicate.example.com/metadata")
                .name("First SP")
                .acsUrl("https://duplicate.example.com/acs1")
                .enabled(true)
                .build());

        try {
            spRepository.saveAndFlush(SamlServiceProvider.builder()
                    .tenant(tenant)
                    .entityId("https://duplicate.example.com/metadata")
                    .name("Second SP")
                    .acsUrl("https://duplicate.example.com/acs2")
                    .enabled(true)
                    .build());
            throw new AssertionError("Expected unique constraint violation, none thrown");
        } catch (org.springframework.dao.DataIntegrityViolationException expected) {
            // The constraint is doing its job.
        }
    }

    @Test
    @Transactional
    @DisplayName("IdP metadata generation produces valid XML with a real signing key")
    void idpMetadata_generatesWithRealSigningKey() {
        Tenant tenant = tenantRepository.findBySlug("default").orElseThrow();

        String metadata = samlIdpService.generateMetadata(tenant, "https://sso.example.com");

        assertThat(metadata).contains("EntityDescriptor");
        assertThat(metadata).contains("entityID=\"https://sso.example.com/t/default/saml2/idp/metadata\"");
        assertThat(metadata).contains("IDPSSODescriptor");
        assertThat(metadata).contains("KeyDescriptor");
        assertThat(metadata).contains("X509Certificate");
        assertThat(metadata).contains("SingleSignOnService");
        assertThat(metadata).contains("Location=\"https://sso.example.com/t/default/saml2/idp/sso\"");

        // Verify the signing key was actually persisted
        TenantSigningKey key = signingKeyRepository
                .findFirstByTenantIdAndActiveTrue(tenant.getId()).orElseThrow();
        assertThat(key.getKid()).startsWith("wf-");
        assertThat(key.getAlgorithm()).isEqualTo("RS256");
        assertThat(key.getPublicKeyPem()).contains("BEGIN PUBLIC KEY");
    }

    @Test
    @Transactional
    @DisplayName("SAML response can be built and signed end-to-end for a registered SP")
    void samlResponse_builtAndSignedEndToEnd() {
        Tenant tenant = tenantRepository.findBySlug("default").orElseThrow();

        // Create a test user
        User user = userRepository.save(User.builder()
                .tenant(tenant)
                .username("saml-test-user")
                .email("saml@test.com")
                .name("SAML Test User")
                .provider(AuthProvider.LOCAL)
                .providerId("saml-test-user")
                .active(true)
                .build());

        // Create a test SP
        SamlServiceProvider sp = spRepository.save(SamlServiceProvider.builder()
                .tenant(tenant)
                .entityId("https://response-sp.example.com/metadata")
                .name("Response Test SP")
                .acsUrl("https://response-sp.example.com/acs")
                .nameIdFormat("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress")
                .enabled(true)
                .build());

        String base64Response = samlIdpService.buildSamlResponse(tenant, user, sp, "_request-123");

        assertThat(base64Response).isNotBlank();

        // Decode and verify it contains expected SAML elements
        String decoded = new String(java.util.Base64.getDecoder().decode(base64Response));
        assertThat(decoded).contains("samlp:Response");
        assertThat(decoded).contains("saml:Assertion");
        assertThat(decoded).contains("saml@test.com");
        assertThat(decoded).contains("InResponseTo=\"_request-123\"");
        // Verify the response is signed (XML-DSig present)
        assertThat(decoded).contains("SignatureValue");
    }
}
