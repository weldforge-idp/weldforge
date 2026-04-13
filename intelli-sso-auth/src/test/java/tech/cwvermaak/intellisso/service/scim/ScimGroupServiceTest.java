package tech.cwvermaak.intellisso.service.scim;

import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import jakarta.persistence.EntityNotFoundException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
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

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicLong;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

class ScimGroupServiceTest {

    private TenantAccessor tenantAccessor;
    private ScimGroupRepository groupRepository;
    private UserRepository userRepository;
    private AuditService auditService;
    private ScimGroupService service;

    private Tenant tenant;
    private final List<ScimGroup> groupStore = new ArrayList<>();
    private final List<User> userStore = new ArrayList<>();
    private final AtomicLong idSeq = new AtomicLong(1000);

    private User alice;
    private User bob;

    @BeforeEach
    void setUp() {
        tenantAccessor = mock(TenantAccessor.class);
        groupRepository = mock(ScimGroupRepository.class);
        userRepository = mock(UserRepository.class);
        auditService = mock(AuditService.class);

        tenant = Tenant.builder().id(1L).slug("acme").name("Acme").build();
        alice = User.builder().id(42L).tenant(tenant).email("alice@acme.test").username("alice@acme.test").active(true).build();
        bob   = User.builder().id(43L).tenant(tenant).email("bob@acme.test").username("bob@acme.test").active(true).build();
        userStore.add(alice);
        userStore.add(bob);

        when(tenantAccessor.requireTenant()).thenReturn(tenant);
        when(tenantAccessor.requireTenantId()).thenReturn(1L);

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
        when(groupRepository.findByTenantId(1L)).thenAnswer(inv -> List.copyOf(groupStore));
        when(groupRepository.findByIdAndTenantId(anyLong(), eq(1L))).thenAnswer(inv -> {
            Long id = inv.getArgument(0);
            return groupStore.stream().filter(g -> id.equals(g.getId())).findFirst();
        });
        when(groupRepository.findByTenantIdAndNameIgnoreCase(eq(1L), anyString())).thenAnswer(inv -> {
            String name = inv.getArgument(1);
            return groupStore.stream().filter(g -> name.equalsIgnoreCase(g.getName())).findFirst();
        });
        when(groupRepository.existsByTenantIdAndNameIgnoreCase(eq(1L), anyString())).thenAnswer(inv -> {
            String name = inv.getArgument(1);
            return groupStore.stream().anyMatch(g -> name.equalsIgnoreCase(g.getName()));
        });

        when(userRepository.findByIdAndTenantId(anyLong(), eq(1L))).thenAnswer(inv -> {
            Long id = inv.getArgument(0);
            return userStore.stream().filter(u -> id.equals(u.getId())).findFirst();
        });

        GroupRoleMappingService groupRoleMappingService = mock(GroupRoleMappingService.class);
        service = new ScimGroupService(tenantAccessor, groupRepository, userRepository, auditService, new SimpleMeterRegistry(), groupRoleMappingService);
    }

    private ScimGroupDto sample(String displayName, Long... memberIds) {
        List<ScimGroupMemberDto> members = new ArrayList<>();
        for (Long id : memberIds) {
            members.add(ScimGroupMemberDto.builder().value(String.valueOf(id)).build());
        }
        return ScimGroupDto.builder()
                .displayName(displayName)
                .members(members.isEmpty() ? null : members)
                .build();
    }

    @Test
    @DisplayName("create persists the group with resolved members and audits")
    void create_resolvesMembers() {
        ScimGroupDto created = service.create(sample("Engineers", 42L, 43L), null, null);

        assertThat(created.getId()).isNotBlank();
        assertThat(created.getDisplayName()).isEqualTo("Engineers");
        assertThat(created.getMembers()).hasSize(2);
        assertThat(created.getMembers())
                .extracting(ScimGroupMemberDto::getValue)
                .containsExactlyInAnyOrder("42", "43");

        verify(auditService, atLeastOnce()).log(any());
    }

    @Test
    @DisplayName("create silently drops members whose ids do not exist in this tenant")
    void create_dropsCrossTenantMembers() {
        ScimGroupDto created = service.create(sample("Engineers", 42L, 9999L), null, null);

        assertThat(created.getMembers()).hasSize(1);
        assertThat(created.getMembers().get(0).getValue()).isEqualTo("42");
    }

    @Test
    @DisplayName("create rejects a duplicate displayName in the same tenant")
    void create_duplicateRejected() {
        service.create(sample("Engineers"), null, null);
        assertThatThrownBy(() -> service.create(sample("Engineers"), null, null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("already in use");
    }

    @Test
    @DisplayName("list returns every group in the tenant when no filter is provided")
    void list_all() {
        service.create(sample("Engineers"), null, null);
        service.create(sample("Designers"), null, null);

        ScimListResponseDto<ScimGroupDto> page = service.list(null, 1, 100, null, null);
        assertThat(page.getTotalResults()).isEqualTo(2);
        assertThat(page.getResources()).hasSize(2);
    }

    @Test
    @DisplayName("PATCH add members appends and emits a member.add audit")
    void patch_addMember() {
        ScimGroupDto created = service.create(sample("Engineers"), null, null);
        Long id = Long.valueOf(created.getId());

        ScimPatchRequestDto patch = ScimPatchRequestDto.builder()
                .operations(List.of(ScimPatchRequestDto.Operation.builder()
                        .op("add").path("members")
                        .value(List.of(java.util.Map.of("value", "42")))
                        .build()))
                .build();
        ScimGroupDto patched = service.patch(id, patch, null, null);

        assertThat(patched.getMembers()).extracting(ScimGroupMemberDto::getValue).contains("42");

        ArgumentCaptor<AuditEvent.AuditEventBuilder> captor =
                ArgumentCaptor.forClass(AuditEvent.AuditEventBuilder.class);
        verify(auditService, atLeastOnce()).log(captor.capture());
        assertThat(captor.getAllValues().stream().map(b -> b.build().getEventType()).toList())
                .contains(ScimGroupService.AUDIT_MEMBER_ADD);
    }

    @Test
    @DisplayName("PATCH remove members shrinks the set and emits a member.remove audit")
    void patch_removeMember() {
        ScimGroupDto created = service.create(sample("Engineers", 42L, 43L), null, null);
        Long id = Long.valueOf(created.getId());

        ScimPatchRequestDto patch = ScimPatchRequestDto.builder()
                .operations(List.of(ScimPatchRequestDto.Operation.builder()
                        .op("remove").path("members")
                        .value(List.of(java.util.Map.of("value", "42")))
                        .build()))
                .build();
        ScimGroupDto patched = service.patch(id, patch, null, null);

        assertThat(patched.getMembers()).hasSize(1);
        assertThat(patched.getMembers().get(0).getValue()).isEqualTo("43");

        ArgumentCaptor<AuditEvent.AuditEventBuilder> captor =
                ArgumentCaptor.forClass(AuditEvent.AuditEventBuilder.class);
        verify(auditService, atLeastOnce()).log(captor.capture());
        assertThat(captor.getAllValues().stream().map(b -> b.build().getEventType()).toList())
                .contains(ScimGroupService.AUDIT_MEMBER_REMOVE);
    }

    @Test
    @DisplayName("PUT replaces the group, including memberships")
    void replace_overwritesMembers() {
        ScimGroupDto created = service.create(sample("Engineers", 42L), null, null);
        Long id = Long.valueOf(created.getId());

        ScimGroupDto put = ScimGroupDto.builder()
                .displayName("Engineering")
                .members(List.of(ScimGroupMemberDto.builder().value("43").build()))
                .build();
        ScimGroupDto replaced = service.replace(id, put, null, null);

        assertThat(replaced.getDisplayName()).isEqualTo("Engineering");
        assertThat(replaced.getMembers()).extracting(ScimGroupMemberDto::getValue)
                .containsExactly("43");
    }

    @Test
    @DisplayName("delete throws when the group belongs to another tenant")
    void delete_crossTenantNotFound() {
        assertThatThrownBy(() -> service.delete(99999L))
                .isInstanceOf(EntityNotFoundException.class);
    }
}
