package tech.cwvermaak.weldforge.bdd;

import io.cucumber.java.en.Given;
import io.cucumber.java.en.Then;
import io.cucumber.java.en.When;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import tech.cwvermaak.weldforge.config.tenant.TenantAccessor;
import tech.cwvermaak.weldforge.model.*;
import tech.cwvermaak.weldforge.repository.*;
import tech.cwvermaak.weldforge.service.GroupRoleMappingService;
import tech.cwvermaak.weldforge.service.audit.AuditService;
import tech.cwvermaak.weldforge.service.scim.ScimGroupService;

import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.atomic.AtomicLong;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

public class GroupRoleBindingSteps {

    private final TestWorld world;

    private TenantAccessor tenantAccessor;
    private GroupRoleMappingRepository mappingRepository;
    private ScimGroupRepository scimGroupRepository;
    private RoleRepository roleRepository;
    private UserRepository userRepository;
    private AuditService auditService;
    private GroupRoleMappingService mappingService;
    private ScimGroupService scimGroupService;

    private Tenant acme;
    private final Map<String, Tenant> tenantsBySlug = new HashMap<>();
    private final Map<String, Role> rolesByName = new HashMap<>();
    private final Map<String, ScimGroup> groupsByName = new HashMap<>();
    private final List<GroupRoleMapping> mappingStore = new ArrayList<>();
    private final List<ScimGroup> groupStore = new ArrayList<>();
    private final List<User> userStore = new ArrayList<>();
    private final AtomicLong idSeq = new AtomicLong(8000);

    private User alice;

    public GroupRoleBindingSteps(TestWorld world) {
        this.world = world;
    }

    private void ensureWired() {
        if (mappingService != null) return;

        tenantAccessor = mock(TenantAccessor.class);
        mappingRepository = mock(GroupRoleMappingRepository.class);
        scimGroupRepository = mock(ScimGroupRepository.class);
        roleRepository = mock(RoleRepository.class);
        userRepository = mock(UserRepository.class);
        auditService = mock(AuditService.class);

        when(tenantAccessor.requireTenant()).thenAnswer(inv -> acme);
        when(tenantAccessor.requireTenantId()).thenAnswer(inv -> acme == null ? null : acme.getId());

        // Mapping repository mocks
        when(mappingRepository.save(any(GroupRoleMapping.class))).thenAnswer(inv -> {
            GroupRoleMapping m = inv.getArgument(0);
            if (m.getId() == null) {
                m.setId(idSeq.getAndIncrement());
                mappingStore.add(m);
            }
            return m;
        });
        when(mappingRepository.findByTenantId(anyLong())).thenAnswer(inv -> {
            Long tid = inv.getArgument(0);
            return mappingStore.stream().filter(m -> m.getTenant().getId().equals(tid)).toList();
        });
        when(mappingRepository.findByTenantIdAndScimGroupIdIn(anyLong(), anyCollection())).thenAnswer(inv -> {
            Long tid = inv.getArgument(0);
            Collection<Long> groupIds = inv.getArgument(1);
            return mappingStore.stream()
                    .filter(m -> m.getTenant().getId().equals(tid) && groupIds.contains(m.getScimGroup().getId()))
                    .toList();
        });
        when(mappingRepository.findByIdAndTenantId(anyLong(), anyLong())).thenAnswer(inv -> {
            Long id = inv.getArgument(0);
            Long tid = inv.getArgument(1);
            return mappingStore.stream()
                    .filter(m -> id.equals(m.getId()) && m.getTenant().getId().equals(tid))
                    .findFirst();
        });

        // ScimGroup repository mocks
        when(scimGroupRepository.findByTenantId(anyLong())).thenAnswer(inv -> {
            Long tid = inv.getArgument(0);
            return groupStore.stream().filter(g -> g.getTenant().getId().equals(tid)).toList();
        });
        when(scimGroupRepository.findByIdAndTenantId(anyLong(), anyLong())).thenAnswer(inv -> {
            Long id = inv.getArgument(0);
            Long tid = inv.getArgument(1);
            return groupStore.stream()
                    .filter(g -> id.equals(g.getId()) && g.getTenant().getId().equals(tid))
                    .findFirst();
        });
        when(scimGroupRepository.findByTenantIdAndNameIgnoreCase(anyLong(), anyString())).thenAnswer(inv -> {
            Long tid = inv.getArgument(0);
            String name = inv.getArgument(1);
            return groupStore.stream()
                    .filter(g -> g.getTenant().getId().equals(tid) && name.equalsIgnoreCase(g.getName()))
                    .findFirst();
        });
        when(scimGroupRepository.existsByTenantIdAndNameIgnoreCase(anyLong(), anyString())).thenAnswer(inv -> {
            Long tid = inv.getArgument(0);
            String name = inv.getArgument(1);
            return groupStore.stream()
                    .anyMatch(g -> g.getTenant().getId().equals(tid) && name.equalsIgnoreCase(g.getName()));
        });
        when(scimGroupRepository.save(any(ScimGroup.class))).thenAnswer(inv -> inv.getArgument(0));

        // Role repository mocks
        when(roleRepository.findByIdAndTenantId(anyLong(), anyLong())).thenAnswer(inv -> {
            Long id = inv.getArgument(0);
            Long tid = inv.getArgument(1);
            return rolesByName.values().stream()
                    .filter(r -> id.equals(r.getId()) && r.getTenant().getId().equals(tid))
                    .findFirst();
        });

        // User repository mocks
        when(userRepository.findByIdAndTenantId(anyLong(), anyLong())).thenAnswer(inv -> {
            Long id = inv.getArgument(0);
            Long tid = inv.getArgument(1);
            return userStore.stream()
                    .filter(u -> id.equals(u.getId()) && u.getTenant().getId().equals(tid))
                    .findFirst();
        });
        when(userRepository.save(any(User.class))).thenAnswer(inv -> inv.getArgument(0));

        // Audit mocks
        doAnswer(inv -> {
            AuditEvent.AuditEventBuilder builder = inv.getArgument(0);
            world.auditLog.add(builder.build());
            return null;
        }).when(auditService).log(any());
        doAnswer(inv -> {
            world.auditLog.add(AuditEvent.builder()
                    .eventType(inv.getArgument(0))
                    .outcome(AuditEvent.Outcome.SUCCESS)
                    .build());
            return null;
        }).when(auditService).recordUserAction(anyString(), any(), anyString(), anyString(), any());
        doAnswer(inv -> {
            world.auditLog.add(AuditEvent.builder()
                    .eventType(inv.getArgument(0))
                    .outcome(AuditEvent.Outcome.SUCCESS)
                    .build());
            return null;
        }).when(auditService).recordAdmin(anyString(), any(), anyString(), anyString(), any());

        mappingService = new GroupRoleMappingService(tenantAccessor, mappingRepository,
                scimGroupRepository, roleRepository, userRepository, auditService);

        scimGroupService = new ScimGroupService(tenantAccessor, scimGroupRepository,
                userRepository, auditService, new SimpleMeterRegistry(), mappingService);
    }

    @Given("tenant {string} exists for group-role binding")
    public void tenantExists(String slug) {
        ensureWired();
        acme = Tenant.builder().id(idSeq.getAndIncrement()).slug(slug).name(slug).build();
        tenantsBySlug.put(slug, acme);
    }

    @Given("role {string} exists in tenant {string}")
    public void roleExists(String roleName, String slug) {
        Tenant t = tenantsBySlug.get(slug);
        Role role = Role.builder()
                .id(idSeq.getAndIncrement())
                .tenant(t)
                .name(roleName)
                .build();
        rolesByName.put(roleName, role);
    }

    @Given("SCIM group {string} exists in tenant {string}")
    public void groupExists(String groupName, String slug) {
        Tenant t = tenantsBySlug.get(slug);
        ScimGroup group = ScimGroup.builder()
                .id(idSeq.getAndIncrement())
                .tenant(t)
                .name(groupName)
                .displayName(groupName)
                .members(new HashSet<>())
                .createdAt(LocalDateTime.now())
                .updatedAt(LocalDateTime.now())
                .build();
        groupsByName.put(groupName, group);
        groupStore.add(group);
    }

    @Given("user {string} exists for group-role binding in tenant {string}")
    public void userExists(String email, String slug) {
        Tenant t = tenantsBySlug.get(slug);
        alice = User.builder()
                .id(idSeq.getAndIncrement())
                .tenant(t)
                .email(email)
                .username(email)
                .active(true)
                .provider(AuthProvider.LOCAL)
                .providerId("local")
                .build();
        userStore.add(alice);
    }

    @Given("group {string} is mapped to role {string} with priority {int}")
    public void createMapping(String groupName, String roleName, int priority) {
        ScimGroup group = groupsByName.get(groupName);
        Role role = rolesByName.get(roleName);
        GroupRoleMapping mapping = GroupRoleMapping.builder()
                .id(idSeq.getAndIncrement())
                .tenant(acme)
                .scimGroup(group)
                .role(role)
                .priority(priority)
                .build();
        mappingStore.add(mapping);
    }

    @Given("tenant {string} exists for group-role binding with role {string} and group {string}")
    public void otherTenantWithRoleAndGroup(String slug, String roleName, String groupName) {
        Tenant other = Tenant.builder().id(idSeq.getAndIncrement()).slug(slug).name(slug).build();
        tenantsBySlug.put(slug, other);
        Role role = Role.builder()
                .id(idSeq.getAndIncrement())
                .tenant(other)
                .name(roleName)
                .build();
        rolesByName.put(roleName, role);
        ScimGroup group = ScimGroup.builder()
                .id(idSeq.getAndIncrement())
                .tenant(other)
                .name(groupName)
                .displayName(groupName)
                .members(new HashSet<>())
                .createdAt(LocalDateTime.now())
                .updatedAt(LocalDateTime.now())
                .build();
        groupsByName.put(groupName, group);
        groupStore.add(group);
    }

    @Given("group {string} is mapped to role {string} in tenant {string}")
    public void createMappingInTenant(String groupName, String roleName, String slug) {
        Tenant t = tenantsBySlug.get(slug);
        ScimGroup group = groupsByName.get(groupName);
        Role role = rolesByName.get(roleName);
        GroupRoleMapping mapping = GroupRoleMapping.builder()
                .id(idSeq.getAndIncrement())
                .tenant(t)
                .scimGroup(group)
                .role(role)
                .priority(0)
                .build();
        mappingStore.add(mapping);
    }

    @Given("alice is a member of {string} and {string} for group-role binding")
    public void aliceIsMember(String group1, String group2) {
        groupsByName.get(group1).getMembers().add(alice);
        groupsByName.get(group2).getMembers().add(alice);
    }

    @Given("group-role mappings are applied for alice")
    public void applyMappingsForAlice() {
        mappingService.applyMappings(acme.getId(), alice.getId());
    }

    @When("alice is added to SCIM group {string} via group-role binding")
    public void addAliceToGroup(String groupName) {
        ScimGroup group = groupsByName.get(groupName);
        group.getMembers().add(alice);
        // Trigger role resolution
        mappingService.applyMappings(acme.getId(), alice.getId());
    }

    @When("alice is removed from SCIM group {string} via group-role binding")
    public void removeAliceFromGroup(String groupName) {
        ScimGroup group = groupsByName.get(groupName);
        group.getMembers().removeIf(u -> u.getId().equals(alice.getId()));
        // Trigger role resolution
        mappingService.applyMappings(acme.getId(), alice.getId());
    }

    @Then("alice's role is {string}")
    public void aliceRoleIs(String expected) {
        assertThat(alice.getRole()).isNotNull();
        assertThat(alice.getRole().getName()).isEqualTo(expected);
    }

    @Then("alice's role is not {string}")
    public void aliceRoleIsNot(String notExpected) {
        if (alice.getRole() == null) return;
        assertThat(alice.getRole().getName()).isNotEqualTo(notExpected);
    }

    @Then("a {string} audit event is recorded for group-role binding")
    public void auditRecorded(String type) {
        assertThat(world.auditLog)
                .extracting(AuditEvent::getEventType)
                .contains(type);
    }
}
