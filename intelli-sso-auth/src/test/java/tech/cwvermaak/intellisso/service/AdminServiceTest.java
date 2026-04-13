package tech.cwvermaak.intellisso.service;

import jakarta.persistence.EntityNotFoundException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import tech.cwvermaak.intellisso.config.tenant.TenantAccessor;
import tech.cwvermaak.intellisso.model.Role;
import tech.cwvermaak.intellisso.model.Tenant;
import tech.cwvermaak.intellisso.model.User;
import tech.cwvermaak.intellisso.model.dto.RoleDto;
import tech.cwvermaak.intellisso.repository.AppClientRepository;
import tech.cwvermaak.intellisso.repository.EnvironmentRepository;
import tech.cwvermaak.intellisso.repository.RoleRepository;
import tech.cwvermaak.intellisso.repository.UserRepository;
import tech.cwvermaak.intellisso.service.audit.AuditService;
import tech.cwvermaak.intellisso.service.mfa.MfaService;

import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/**
 * Focus: every list/read/write on AdminService must pass through the
 * caller's tenant id. A test for the isolation contract — not for plumbing.
 */
class AdminServiceTest {

    private TenantAccessor tenantAccessor;
    private RoleRepository roleRepo;
    private UserRepository userRepo;
    private EnvironmentRepository envRepo;
    private AppClientRepository appClientRepo;
    private MfaService mfaService;
    private AuditService auditService;

    private AdminService admin;
    private Tenant tenant;

    @BeforeEach
    void setUp() {
        tenantAccessor = mock(TenantAccessor.class);
        roleRepo = mock(RoleRepository.class);
        userRepo = mock(UserRepository.class);
        envRepo = mock(EnvironmentRepository.class);
        appClientRepo = mock(AppClientRepository.class);
        mfaService = mock(MfaService.class);
        auditService = mock(AuditService.class);

        admin = new AdminService(tenantAccessor, roleRepo, userRepo, envRepo,
                appClientRepo, mfaService, auditService);

        tenant = Tenant.builder().id(7L).slug("acme").name("Acme").build();
    }

    @Test
    @DisplayName("listRoles queries by the caller's tenant id, never the full table")
    void listRoles_scopedByCallersTenant() {
        when(tenantAccessor.requireTenantId()).thenReturn(7L);
        when(roleRepo.findByTenantId(7L)).thenReturn(List.of(
                Role.builder().id(1L).tenant(tenant).name("admin").build()));

        admin.listRoles();

        verify(roleRepo).findByTenantId(7L);
        verify(roleRepo, never()).findAll();
    }

    @Test
    @DisplayName("createRole enforces unique names within the tenant")
    void createRole_rejectsDuplicateInSameTenant() {
        when(tenantAccessor.requireTenant()).thenReturn(tenant);
        when(roleRepo.existsByTenantIdAndNameIgnoreCase(7L, "admin")).thenReturn(true);

        assertThatThrownBy(() -> admin.createRole(RoleDto.builder().name("admin").build()))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("already exists");

        verify(roleRepo, never()).save(any());
    }

    @Test
    @DisplayName("resetUserMfa fails cleanly when the target belongs to another tenant")
    void resetUserMfa_crossTenantDenied() {
        when(tenantAccessor.requireTenantId()).thenReturn(7L);
        when(userRepo.findByIdAndTenantId(999L, 7L)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> admin.resetUserMfa(999L))
                .isInstanceOf(EntityNotFoundException.class);

        // Never reached the MFA wipe — the tenant check stopped it.
        verify(mfaService, never()).adminReset(any(), any());
    }

    @Test
    @DisplayName("resetUserMfa delegates to MfaService.adminReset when the target is in the same tenant")
    void resetUserMfa_sameTenant_wipes() {
        User target = User.builder().id(42L).tenant(tenant).email("alice@acme.test").build();
        when(tenantAccessor.requireTenantId()).thenReturn(7L);
        when(userRepo.findByIdAndTenantId(42L, 7L)).thenReturn(Optional.of(target));
        when(mfaService.adminReset(any(), eq(target))).thenReturn(3);

        int removed = admin.resetUserMfa(42L);

        assertThat(removed).isEqualTo(3);
        verify(mfaService).adminReset(any(), eq(target));
    }
}
