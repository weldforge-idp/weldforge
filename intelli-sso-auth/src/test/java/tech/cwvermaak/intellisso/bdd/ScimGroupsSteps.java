package tech.cwvermaak.intellisso.bdd;

import io.cucumber.java.en.Given;
import io.cucumber.java.en.Then;
import io.cucumber.java.en.When;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import tech.cwvermaak.intellisso.config.tenant.TenantAccessor;
import tech.cwvermaak.intellisso.model.AuditEvent;
import tech.cwvermaak.intellisso.model.ScimGroup;
import tech.cwvermaak.intellisso.model.Tenant;
import tech.cwvermaak.intellisso.model.User;
import tech.cwvermaak.intellisso.model.dto.scim.ScimGroupDto;
import tech.cwvermaak.intellisso.model.dto.scim.ScimGroupMemberDto;
import tech.cwvermaak.intellisso.model.dto.scim.ScimListResponseDto;
import tech.cwvermaak.intellisso.model.dto.scim.ScimPatchRequestDto;
import tech.cwvermaak.intellisso.repository.ScimGroupRepository;
import tech.cwvermaak.intellisso.repository.UserRepository;
import tech.cwvermaak.intellisso.service.GroupRoleMappingService;
import tech.cwvermaak.intellisso.service.audit.AuditService;
import tech.cwvermaak.intellisso.service.scim.ScimGroupService;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

public class ScimGroupsSteps {

    private final TestWorld world;

    private TenantAccessor tenantAccessor;
    private ScimGroupRepository groupRepository;
    private UserRepository userRepository;
    private AuditService auditService;
    private ScimGroupService groupService;

    private Tenant acme;
    private final Map<String, Tenant> tenantsByName = new HashMap<>();
    private final List<ScimGroup> groupStore = new ArrayList<>();
    private final List<User> userStore = new ArrayList<>();
    private final AtomicLong idSeq = new AtomicLong(2000);

    private ScimGroupDto lastGroup;
    private ScimListResponseDto<ScimGroupDto> lastList;

    public ScimGroupsSteps(TestWorld world) {
        this.world = world;
    }

    private void ensureWired() {
        if (groupService != null) return;

        tenantAccessor = mock(TenantAccessor.class);
        groupRepository = mock(ScimGroupRepository.class);
        userRepository = mock(UserRepository.class);
        auditService = mock(AuditService.class);

        when(tenantAccessor.requireTenant()).thenAnswer(inv -> acme);
        when(tenantAccessor.requireTenantId()).thenAnswer(inv -> acme == null ? null : acme.getId());

        when(groupRepository.save(any(ScimGroup.class))).thenAnswer(inv -> {
            ScimGroup g = inv.getArgument(0);
            if (g.getId() == null) {
                g.setId(idSeq.getAndIncrement());
                if (g.getCreatedAt() == null) g.setCreatedAt(LocalDateTime.now());
                g.setUpdatedAt(LocalDateTime.now());
                groupStore.add(g);
            }
            return g;
        });
        when(groupRepository.findByTenantId(anyLong())).thenAnswer(inv -> {
            Long tid = inv.getArgument(0);
            return groupStore.stream().filter(g -> g.getTenant().getId().equals(tid)).toList();
        });
        when(groupRepository.findByIdAndTenantId(anyLong(), anyLong())).thenAnswer(inv -> {
            Long id = inv.getArgument(0);
            Long tid = inv.getArgument(1);
            return groupStore.stream()
                    .filter(g -> id.equals(g.getId()) && g.getTenant().getId().equals(tid))
                    .findFirst();
        });
        when(groupRepository.findByTenantIdAndNameIgnoreCase(anyLong(), anyString())).thenAnswer(inv -> {
            Long tid = inv.getArgument(0);
            String name = inv.getArgument(1);
            return groupStore.stream()
                    .filter(g -> g.getTenant().getId().equals(tid) && name.equalsIgnoreCase(g.getName()))
                    .findFirst();
        });
        when(groupRepository.existsByTenantIdAndNameIgnoreCase(anyLong(), anyString())).thenAnswer(inv -> {
            Long tid = inv.getArgument(0);
            String name = inv.getArgument(1);
            return groupStore.stream()
                    .anyMatch(g -> g.getTenant().getId().equals(tid) && name.equalsIgnoreCase(g.getName()));
        });

        when(userRepository.findByIdAndTenantId(anyLong(), anyLong())).thenAnswer(inv -> {
            Long id = inv.getArgument(0);
            Long tid = inv.getArgument(1);
            return userStore.stream()
                    .filter(u -> id.equals(u.getId()) && u.getTenant().getId().equals(tid))
                    .findFirst();
        });

        // Capture audit events into the world for assertions across step classes.
        doAnswer(inv -> {
            AuditEvent.AuditEventBuilder builder = inv.getArgument(0);
            world.auditLog.add(builder.build());
            return null;
        }).when(auditService).log(any());

        GroupRoleMappingService groupRoleMappingService = mock(GroupRoleMappingService.class);
        groupService = new ScimGroupService(tenantAccessor, groupRepository, userRepository, auditService, new SimpleMeterRegistry(), groupRoleMappingService);
    }

    private User createUser(String email, Tenant tenant) {
        User u = User.builder()
                .id(idSeq.getAndIncrement())
                .tenant(tenant)
                .email(email)
                .username(email)
                .active(true)
                .build();
        userStore.add(u);
        return u;
    }

    @Given("tenant {string} exists for SCIM groups")
    public void tenantExistsForGroups(String slug) {
        acme = Tenant.builder().id(1L).slug(slug).name(slug).build();
        tenantsByName.put(slug, acme);
        ensureWired();
    }

    @Given("users {string} and {string} exist in tenant {string}")
    public void usersExist(String email1, String email2, String slug) {
        Tenant t = tenantsByName.get(slug);
        createUser(email1, t);
        createUser(email2, t);
    }

    private User userByEmail(String email) {
        return userStore.stream().filter(u -> u.getEmail().equals(email)).findFirst().orElseThrow();
    }

    @When("a SCIM client creates group {string} in tenant {string}")
    public void createGroup(String displayName, String slug) {
        ScimGroupDto incoming = ScimGroupDto.builder().displayName(displayName).build();
        lastGroup = groupService.create(incoming, "https://wf.test/scim/v2/" + slug + "/Groups",
                "https://wf.test/scim/v2/" + slug + "/Users");
    }

    @When("a SCIM client creates group {string} in tenant {string} with members alice and bob")
    public void createGroupWithMembers(String displayName, String slug) {
        Long aliceId = userByEmail("alice@acme.test").getId();
        Long bobId   = userByEmail("bob@acme.test").getId();
        ScimGroupDto incoming = ScimGroupDto.builder()
                .displayName(displayName)
                .members(List.of(
                        ScimGroupMemberDto.builder().value(String.valueOf(aliceId)).build(),
                        ScimGroupMemberDto.builder().value(String.valueOf(bobId)).build()))
                .build();
        lastGroup = groupService.create(incoming,
                "https://wf.test/scim/v2/" + slug + "/Groups",
                "https://wf.test/scim/v2/" + slug + "/Users");
    }

    @Then("the group is created")
    public void groupCreated() {
        assertThat(lastGroup).isNotNull();
        assertThat(lastGroup.getId()).isNotBlank();
    }

    @When("a SCIM client adds alice to the group {string}")
    public void addAlice(String displayName) {
        addMember(displayName, "alice@acme.test");
    }

    @When("a SCIM client adds bob to the group {string}")
    public void addBob(String displayName) {
        addMember(displayName, "bob@acme.test");
    }

    private void addMember(String displayName, String email) {
        ScimGroup group = findGroup(displayName);
        Long uid = userByEmail(email).getId();
        ScimPatchRequestDto patch = ScimPatchRequestDto.builder()
                .operations(List.of(ScimPatchRequestDto.Operation.builder()
                        .op("add").path("members")
                        .value(List.of(Map.of("value", String.valueOf(uid))))
                        .build()))
                .build();
        lastGroup = groupService.patch(group.getId(), patch, null, null);
    }

    @When("a SCIM client removes alice from the group {string}")
    public void removeAlice(String displayName) {
        ScimGroup group = findGroup(displayName);
        Long uid = userByEmail("alice@acme.test").getId();
        ScimPatchRequestDto patch = ScimPatchRequestDto.builder()
                .operations(List.of(ScimPatchRequestDto.Operation.builder()
                        .op("remove").path("members")
                        .value(List.of(Map.of("value", String.valueOf(uid))))
                        .build()))
                .build();
        lastGroup = groupService.patch(group.getId(), patch, null, null);
    }

    @When("a SCIM client PUTs the group {string} with only bob as a member")
    public void putBobOnly(String displayName) {
        ScimGroup group = findGroup(displayName);
        Long uid = userByEmail("bob@acme.test").getId();
        ScimGroupDto put = ScimGroupDto.builder()
                .displayName(displayName)
                .members(List.of(ScimGroupMemberDto.builder().value(String.valueOf(uid)).build()))
                .build();
        lastGroup = groupService.replace(group.getId(), put, null, null);
    }

    @Then("the group {string} has {int} member")
    @Then("the group {string} has {int} members")
    public void groupHasMembers(String displayName, int count) {
        ScimGroup group = findGroup(displayName);
        assertThat(group.getMembers()).hasSize(count);
    }

    @Then("the only member is bob")
    public void onlyMemberIsBob() {
        assertThat(lastGroup.getMembers()).hasSize(1);
        assertThat(lastGroup.getMembers().get(0).getDisplay()).isEqualTo("bob@acme.test");
    }

    @Then("a {string} audit event is recorded for the group")
    public void auditForGroup(String type) {
        assertThat(world.auditLog)
                .extracting(AuditEvent::getEventType)
                .contains(type);
    }

    @Given("tenant {string} exists with its own group {string}")
    public void otherTenantWithGroup(String slug, String displayName) {
        Tenant other = Tenant.builder().id(99L).slug(slug).name(slug).build();
        tenantsByName.put(slug, other);
        ScimGroup g = ScimGroup.builder()
                .id(idSeq.getAndIncrement())
                .tenant(other)
                .name(displayName)
                .displayName(displayName)
                .createdAt(LocalDateTime.now())
                .updatedAt(LocalDateTime.now())
                .build();
        groupStore.add(g);
    }

    @When("a SCIM client lists groups in tenant {string}")
    public void listGroups(String slug) {
        // Groups are listed against the acme tenant (the wired-up one).
        lastList = groupService.list(null, 1, 100,
                "https://wf.test/scim/v2/" + slug + "/Groups",
                "https://wf.test/scim/v2/" + slug + "/Users");
    }

    @Then("the SCIM groups list does not contain a group named {string} from globex")
    public void listExcludesOtherTenant(String displayName) {
        // The tenant the SCIM service queries is the one in TenantAccessor —
        // which we wired to acme. The other tenant's group must NOT show up
        // even though it shares a displayName.
        long fromAcme = lastList.getResources().stream()
                .filter(g -> displayName.equals(g.getDisplayName()))
                .count();
        // Acme has no group with that name (we didn't create one), and the
        // globex group is not in acme's tenant, so the list is empty for it.
        assertThat(fromAcme).isZero();
    }

    private ScimGroup findGroup(String displayName) {
        return groupStore.stream()
                .filter(g -> g.getTenant().getId().equals(acme.getId()))
                .filter(g -> displayName.equalsIgnoreCase(g.getName()))
                .findFirst()
                .orElseThrow(() -> new AssertionError("group not found in acme: " + displayName));
    }
}
