package tech.cwvermaak.intellisso.integration;

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
import tech.cwvermaak.intellisso.config.tenant.TenantContext;
import tech.cwvermaak.intellisso.model.*;
import tech.cwvermaak.intellisso.repository.*;
import tech.cwvermaak.intellisso.service.GroupRoleMappingService;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Integration test for the V15 migration (group_role_mappings table)
 * and the GroupRoleMappingService. Boots a full Spring context against a
 * Testcontainers Postgres instance and exercises:
 *
 *  - V15 migration applies cleanly
 *  - Group-role mapping CRUD via the repository
 *  - Unique constraint on (tenant_id, scim_group_id, role_id)
 *  - applyMappings end-to-end: mapping + group membership = role assignment
 */
@SpringBootTest
@Testcontainers
@EnabledIfSystemProperty(named = "tests.integration", matches = "true")
@DisplayName("Group-role mapping integration: V15 migration, persistence, applyMappings")
class GroupRoleMappingIntegrationTest {

    @Container
    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:16-alpine")
            .withDatabaseName("intellisso_test")
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
    @Autowired private RoleRepository roleRepository;
    @Autowired private ScimGroupRepository scimGroupRepository;
    @Autowired private GroupRoleMappingRepository mappingRepository;
    @Autowired private UserRepository userRepository;
    @Autowired private GroupRoleMappingService mappingService;

    @BeforeEach
    void setTenantContext() {
        Tenant tenant = tenantRepository.findBySlug("default").orElseThrow();
        TenantContext.set("default", tenant.getId(), true);
    }

    @Test
    @DisplayName("V15 migration creates group_role_mappings table successfully")
    void v15Migration_appliesCleanly() {
        assertThat(mappingRepository.findAll()).isNotNull();
    }

    @Test
    @Transactional
    @DisplayName("group-role mapping persists and is retrievable by tenant")
    void groupRoleMapping_persistsAndRetrievable() {
        Tenant tenant = tenantRepository.findBySlug("default").orElseThrow();

        Role role = roleRepository.save(Role.builder()
                .tenant(tenant)
                .name("grm-test-role")
                .description("Role for GRM integration test")
                .build());

        ScimGroup group = scimGroupRepository.save(ScimGroup.builder()
                .tenant(tenant)
                .name("grm-test-group")
                .displayName("GRM Test Group")
                .build());

        GroupRoleMapping mapping = mappingRepository.save(GroupRoleMapping.builder()
                .tenant(tenant)
                .scimGroup(group)
                .role(role)
                .priority(10)
                .build());

        assertThat(mapping.getId()).isNotNull();
        assertThat(mapping.getCreatedAt()).isNotNull();

        var tenantMappings = mappingRepository.findByTenantId(tenant.getId());
        assertThat(tenantMappings).anyMatch(m ->
                m.getScimGroup().getId().equals(group.getId())
                && m.getRole().getId().equals(role.getId())
                && m.getPriority() == 10);
    }

    @Test
    @Transactional
    @DisplayName("unique constraint on (tenant_id, scim_group_id, role_id) prevents duplicates")
    void uniqueConstraint_blocksDuplicateMapping() {
        Tenant tenant = tenantRepository.findBySlug("default").orElseThrow();

        Role role = roleRepository.save(Role.builder()
                .tenant(tenant).name("dup-constraint-role").build());
        ScimGroup group = scimGroupRepository.save(ScimGroup.builder()
                .tenant(tenant).name("dup-constraint-group").displayName("Dup Group").build());

        mappingRepository.save(GroupRoleMapping.builder()
                .tenant(tenant).scimGroup(group).role(role).priority(0).build());

        try {
            mappingRepository.saveAndFlush(GroupRoleMapping.builder()
                    .tenant(tenant).scimGroup(group).role(role).priority(1).build());
            throw new AssertionError("Expected unique constraint violation, none thrown");
        } catch (org.springframework.dao.DataIntegrityViolationException expected) {
            // The constraint is doing its job.
        }
    }

    @Test
    @Transactional
    @DisplayName("applyMappings assigns role to user based on group membership")
    void applyMappings_assignsRoleBasedOnGroupMembership() {
        Tenant tenant = tenantRepository.findBySlug("default").orElseThrow();

        // Create role
        Role role = roleRepository.save(Role.builder()
                .tenant(tenant)
                .name("apply-mappings-role")
                .description("Role assigned by group mapping")
                .build());

        // Create user without a role
        User user = userRepository.save(User.builder()
                .tenant(tenant)
                .username("grm-apply-user")
                .email("grm-apply@test.com")
                .provider(AuthProvider.LOCAL)
                .providerId("grm-apply-user")
                .active(true)
                .build());

        // Create SCIM group with the user as member
        ScimGroup group = ScimGroup.builder()
                .tenant(tenant)
                .name("apply-mappings-group")
                .displayName("Apply Mappings Group")
                .build();
        group.getMembers().add(user);
        group = scimGroupRepository.save(group);

        // Create the mapping
        mappingRepository.save(GroupRoleMapping.builder()
                .tenant(tenant)
                .scimGroup(group)
                .role(role)
                .priority(0)
                .build());

        // Apply mappings
        boolean changed = mappingService.applyMappings(tenant.getId(), user.getId());

        assertThat(changed).isTrue();

        // Verify the user now has the role
        User reloaded = userRepository.findById(user.getId()).orElseThrow();
        assertThat(reloaded.getRole()).isNotNull();
        assertThat(reloaded.getRole().getId()).isEqualTo(role.getId());
    }

    @Test
    @Transactional
    @DisplayName("resolveRole picks the highest-priority (lowest number) mapping")
    void resolveRole_picksHighestPriority() {
        Tenant tenant = tenantRepository.findBySlug("default").orElseThrow();

        Role lowPriorityRole = roleRepository.save(Role.builder()
                .tenant(tenant).name("low-priority-role").build());
        Role highPriorityRole = roleRepository.save(Role.builder()
                .tenant(tenant).name("high-priority-role").build());

        User user = userRepository.save(User.builder()
                .tenant(tenant)
                .username("priority-user")
                .email("priority@test.com")
                .provider(AuthProvider.LOCAL)
                .providerId("priority-user")
                .active(true)
                .build());

        ScimGroup groupA = ScimGroup.builder()
                .tenant(tenant).name("group-a").displayName("Group A").build();
        groupA.getMembers().add(user);
        groupA = scimGroupRepository.save(groupA);

        ScimGroup groupB = ScimGroup.builder()
                .tenant(tenant).name("group-b").displayName("Group B").build();
        groupB.getMembers().add(user);
        groupB = scimGroupRepository.save(groupB);

        // Group A -> low priority role (priority 10)
        mappingRepository.save(GroupRoleMapping.builder()
                .tenant(tenant).scimGroup(groupA).role(lowPriorityRole).priority(10).build());

        // Group B -> high priority role (priority 1, wins)
        mappingRepository.save(GroupRoleMapping.builder()
                .tenant(tenant).scimGroup(groupB).role(highPriorityRole).priority(1).build());

        Optional<Role> resolved = mappingService.resolveRole(tenant.getId(), user.getId());

        assertThat(resolved).isPresent();
        assertThat(resolved.get().getId()).isEqualTo(highPriorityRole.getId());
    }
}
