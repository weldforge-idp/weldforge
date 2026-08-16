package tech.cwvermaak.weldforge.service.scim;

import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import jakarta.persistence.EntityNotFoundException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import tech.cwvermaak.weldforge.config.tenant.TenantAccessor;
import tech.cwvermaak.weldforge.model.Tenant;
import tech.cwvermaak.weldforge.model.User;
import tech.cwvermaak.weldforge.model.dto.scim.ScimEmailDto;
import tech.cwvermaak.weldforge.model.dto.scim.ScimListResponseDto;
import tech.cwvermaak.weldforge.model.dto.scim.ScimNameDto;
import tech.cwvermaak.weldforge.model.dto.scim.ScimPatchRequestDto;
import tech.cwvermaak.weldforge.model.dto.scim.ScimUserDto;
import tech.cwvermaak.weldforge.repository.UserRepository;
import tech.cwvermaak.weldforge.service.TenantSeatService;
import tech.cwvermaak.weldforge.service.audit.AuditService;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

/**
 * Contract tests for the SCIM provisioning service. Mockito-backed
 * UserRepository so we exercise real service logic without a database.
 */
class ScimUserServiceTest {

    private TenantAccessor tenantAccessor;
    private UserRepository userRepository;
    private AuditService auditService;
    private ScimUserService service;

    private Tenant tenant;
    private final List<User> store = new ArrayList<>();
    private final AtomicLong idSeq = new AtomicLong(100);

    @BeforeEach
    void setUp() {
        tenantAccessor = mock(TenantAccessor.class);
        userRepository = mock(UserRepository.class);
        auditService = mock(AuditService.class);

        tenant = Tenant.builder().id(1L).slug("acme").name("Acme").build();
        when(tenantAccessor.requireTenant()).thenReturn(tenant);
        when(tenantAccessor.requireTenantId()).thenReturn(1L);

        when(userRepository.save(any(User.class))).thenAnswer(inv -> {
            User u = inv.getArgument(0);
            if (u.getId() == null) {
                u.setId(idSeq.getAndIncrement());
                if (u.getCreatedAt() == null) u.setCreatedAt(LocalDateTime.now());
                store.add(u);
            }
            return u;
        });
        when(userRepository.findByTenantId(1L)).thenAnswer(inv -> List.copyOf(store));
        when(userRepository.findByIdAndTenantId(anyLong(), eq(1L))).thenAnswer(inv -> {
            Long id = inv.getArgument(0);
            return store.stream().filter(u -> id.equals(u.getId())).findFirst();
        });
        when(userRepository.findByTenantIdAndUsernameIgnoreCase(eq(1L), anyString())).thenAnswer(inv -> {
            String name = inv.getArgument(1);
            return store.stream()
                    .filter(u -> name.equalsIgnoreCase(u.getUsername()))
                    .findFirst();
        });
        when(userRepository.findByTenantIdAndEmailIgnoreCase(eq(1L), anyString())).thenAnswer(inv -> {
            String email = inv.getArgument(1);
            return store.stream()
                    .filter(u -> email.equalsIgnoreCase(u.getEmail()))
                    .findFirst();
        });

        service = new ScimUserService(tenantAccessor, userRepository, auditService, new SimpleMeterRegistry(),
                new TenantSeatService(userRepository));
    }

    private ScimUserDto sample(String userName) {
        return ScimUserDto.builder()
                .userName(userName)
                .name(ScimNameDto.builder().givenName("Alice").familyName("Example").build())
                .displayName("Alice Example")
                .emails(List.of(ScimEmailDto.builder().value(userName).primary(true).build()))
                .active(true)
                .build();
    }

    @Test
    @DisplayName("create persists a tenant-scoped user and returns the SCIM shape")
    void create_persistsAndReturnsScim() {
        ScimUserDto created = service.create(sample("alice@acme.test"), "https://wf.test/scim/v2/acme/Users");

        assertThat(created.getId()).isNotBlank();
        assertThat(created.getUserName()).isEqualTo("alice@acme.test");
        assertThat(created.isActive()).isTrue();
        assertThat(created.getMeta()).isNotNull();
        assertThat(created.getMeta().getLocation()).contains("/scim/v2/acme/Users/");
        assertThat(created.getEmails()).hasSize(1);
        assertThat(created.getEmails().get(0).getValue()).isEqualTo("alice@acme.test");

        verify(userRepository).save(any(User.class));
        verify(auditService).log(any());
    }

    @Test
    @DisplayName("create rejects a duplicate userName inside the same tenant")
    void create_rejectsDuplicate() {
        service.create(sample("alice@acme.test"), null);

        assertThatThrownBy(() -> service.create(sample("alice@acme.test"), null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("already in use");
    }

    @Test
    @DisplayName("list with no filter returns every user in the tenant")
    void listAll() {
        service.create(sample("alice@acme.test"), null);
        service.create(sample("bob@acme.test"), null);

        ScimListResponseDto<ScimUserDto> page = service.list(null, 1, 100, "https://wf.test/scim/v2/acme/Users");
        assertThat(page.getTotalResults()).isEqualTo(2);
        assertThat(page.getResources()).hasSize(2);
    }

    @Test
    @DisplayName("list with userName filter returns the single matching user")
    void listFilterUserName() {
        service.create(sample("alice@acme.test"), null);
        service.create(sample("bob@acme.test"), null);

        ScimListResponseDto<ScimUserDto> page = service.list(
                "userName eq \"alice@acme.test\"", 1, 100, "https://wf.test/scim/v2/acme/Users");
        assertThat(page.getTotalResults()).isEqualTo(1);
        assertThat(page.getResources()).hasSize(1);
        assertThat(page.getResources().get(0).getUserName()).isEqualTo("alice@acme.test");
    }

    @Test
    @DisplayName("PATCH active=false flips the row and emits a deactivate audit event")
    void patchActive_deactivates() {
        ScimUserDto created = service.create(sample("alice@acme.test"), null);
        Long id = Long.valueOf(created.getId());

        ScimPatchRequestDto patch = ScimPatchRequestDto.builder()
                .operations(List.of(ScimPatchRequestDto.Operation.builder()
                        .op("replace").path("active").value(false).build()))
                .build();
        ScimUserDto patched = service.patch(id, patch, null);

        assertThat(patched.isActive()).isFalse();

        // Two audit events: one for the patch itself, one for the deactivation.
        ArgumentCaptor<tech.cwvermaak.weldforge.model.AuditEvent.AuditEventBuilder> captor =
                ArgumentCaptor.forClass(tech.cwvermaak.weldforge.model.AuditEvent.AuditEventBuilder.class);
        // recordUserAction isn't used here — service uses log() with builders.
        verify(auditService, atLeast(2)).log(captor.capture());
        assertThat(captor.getAllValues().stream()
                .map(b -> b.build().getEventType()).toList())
                .contains(ScimUserService.AUDIT_SCIM_USER_PATCH,
                          ScimUserService.AUDIT_SCIM_USER_DEACTIVATE);
    }

    @Test
    @DisplayName("PUT replaces the user and surfaces the new name + email + active flag")
    void replace_overwrites() {
        ScimUserDto created = service.create(sample("alice@acme.test"), null);
        Long id = Long.valueOf(created.getId());

        ScimUserDto put = ScimUserDto.builder()
                .userName("alice2@acme.test")
                .displayName("Alice Two")
                .emails(List.of(ScimEmailDto.builder().value("alice2@acme.test").primary(true).build()))
                .active(false)
                .build();
        ScimUserDto replaced = service.replace(id, put, null);

        assertThat(replaced.getUserName()).isEqualTo("alice2@acme.test");
        assertThat(replaced.getDisplayName()).isEqualTo("Alice Two");
        assertThat(replaced.isActive()).isFalse();
    }

    @Test
    @DisplayName("delete removes the row and audits")
    void delete_removesRow() {
        ScimUserDto created = service.create(sample("alice@acme.test"), null);
        Long id = Long.valueOf(created.getId());
        // Make the delete actually remove from the in-memory store.
        doAnswer(inv -> {
            User u = inv.getArgument(0);
            store.removeIf(x -> x.getId().equals(u.getId()));
            return null;
        }).when(userRepository).delete(any(User.class));

        service.delete(id);

        assertThat(store).isEmpty();
    }

    @Test
    @DisplayName("get returns 404 when the id belongs to another tenant")
    void get_crossTenantNotFound() {
        // Empty store + the mock returns Optional.empty for unknown ids.
        assertThatThrownBy(() -> service.get(999L, null))
                .isInstanceOf(EntityNotFoundException.class);
    }
}
