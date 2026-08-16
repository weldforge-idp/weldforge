package tech.cwvermaak.weldforge.service;

import jakarta.persistence.EntityNotFoundException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import tech.cwvermaak.weldforge.config.tenant.TenantAccessor;
import tech.cwvermaak.weldforge.model.Role;
import tech.cwvermaak.weldforge.model.Tenant;
import tech.cwvermaak.weldforge.model.User;
import tech.cwvermaak.weldforge.model.dto.RoleDto;
import tech.cwvermaak.weldforge.repository.AppClientRepository;
import tech.cwvermaak.weldforge.repository.EnvironmentRepository;
import tech.cwvermaak.weldforge.repository.RoleRepository;
import tech.cwvermaak.weldforge.repository.UserRepository;
import tech.cwvermaak.weldforge.service.audit.AuditService;
import tech.cwvermaak.weldforge.service.mfa.MfaService;

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
    private tech.cwvermaak.weldforge.service.PasswordResetService passwordResetService;

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
        passwordResetService = mock(tech.cwvermaak.weldforge.service.PasswordResetService.class);

        admin = new AdminService(tenantAccessor, roleRepo, userRepo, envRepo,
                appClientRepo, mfaService, auditService, passwordResetService,
                new TenantSeatService(userRepo));

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

    // ─────────────────────────── setUserRole ──────────────────────────────

    @Test
    @DisplayName("setUserRole assigns a tenant-scoped role and bumps tokenVersion to invalidate stale JWTs")
    void setUserRole_happyPath_bumpsTokenVersion() {
        User target = User.builder()
                .id(42L).tenant(tenant).email("alice@acme.test").tokenVersion(3).build();
        Role role = Role.builder().id(11L).tenant(tenant).name("SUPERADMIN").build();
        when(tenantAccessor.requireTenantId()).thenReturn(7L);
        when(userRepo.findByIdAndTenantId(42L, 7L)).thenReturn(Optional.of(target));
        when(roleRepo.findByIdAndTenantId(11L, 7L)).thenReturn(Optional.of(role));
        when(userRepo.save(any())).thenAnswer(inv -> inv.getArgument(0));

        admin.setUserRole(42L, 11L);

        assertThat(target.getRole()).isSameAs(role);
        assertThat(target.getTokenVersion()).isEqualTo(4);
        verify(userRepo).save(target);
        verify(auditService).recordAdmin(eq("user.role.assigned"), any(), any(), eq("42"), any());
    }

    @Test
    @DisplayName("setUserRole(null) clears the assignment so an admin can demote a user")
    void setUserRole_nullClearsAssignment() {
        Role oldRole = Role.builder().id(11L).tenant(tenant).name("SUPERADMIN").build();
        User target = User.builder()
                .id(42L).tenant(tenant).email("alice@acme.test").role(oldRole).tokenVersion(1).build();
        when(tenantAccessor.requireTenantId()).thenReturn(7L);
        when(userRepo.findByIdAndTenantId(42L, 7L)).thenReturn(Optional.of(target));
        when(userRepo.save(any())).thenAnswer(inv -> inv.getArgument(0));

        admin.setUserRole(42L, null);

        assertThat(target.getRole()).isNull();
        assertThat(target.getTokenVersion()).isEqualTo(2);
        // A null roleId means we MUST NOT touch roleRepo.
        verify(roleRepo, never()).findByIdAndTenantId(any(), any());
    }

    @Test
    @DisplayName("setUserRole refuses cross-tenant role assignment — role lookup is tenant-scoped")
    void setUserRole_rolesFromOtherTenantAreInvisible() {
        User target = User.builder().id(42L).tenant(tenant).email("alice@acme.test").build();
        when(tenantAccessor.requireTenantId()).thenReturn(7L);
        when(userRepo.findByIdAndTenantId(42L, 7L)).thenReturn(Optional.of(target));
        when(roleRepo.findByIdAndTenantId(99L, 7L)).thenReturn(Optional.empty()); // role belongs to a different tenant

        assertThatThrownBy(() -> admin.setUserRole(42L, 99L))
                .isInstanceOf(EntityNotFoundException.class);

        verify(userRepo, never()).save(any());
    }

    @Test
    @DisplayName("setUserRole refuses cross-tenant user lookup — user must live in the caller's tenant")
    void setUserRole_crossTenantUserIsHidden() {
        when(tenantAccessor.requireTenantId()).thenReturn(7L);
        when(userRepo.findByIdAndTenantId(42L, 7L)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> admin.setUserRole(42L, 11L))
                .isInstanceOf(EntityNotFoundException.class);

        verify(roleRepo, never()).findByIdAndTenantId(any(), any());
        verify(userRepo, never()).save(any());
    }

    // ─────────────────────────── setAdminRole (B-TEN-1) ───────────────────

    @Test
    @DisplayName("setAdminRole grants a console role to a user in the caller's tenant and bumps tokenVersion")
    void setAdminRole_sameTenant_happyPath() {
        User target = User.builder()
                .id(42L).tenant(tenant).email("alice@acme.test").tokenVersion(2).build();
        when(tenantAccessor.requireTenantId()).thenReturn(7L);
        when(userRepo.findByIdAndTenantId(42L, 7L)).thenReturn(Optional.of(target));
        when(userRepo.save(any())).thenAnswer(inv -> inv.getArgument(0));

        admin.setAdminRole(42L, tech.cwvermaak.weldforge.model.AdminRole.TENANT_ADMIN);

        assertThat(target.getAdminRole()).isEqualTo(tech.cwvermaak.weldforge.model.AdminRole.TENANT_ADMIN);
        assertThat(target.isSuperAdmin()).isFalse();
        assertThat(target.getTokenVersion()).isEqualTo(3);
        verify(userRepo).save(target);
        verify(auditService).recordAdmin(eq("admin.role.assigned"), any(), any(), eq("42"), any());
    }

    @Test
    @DisplayName("setAdminRole refuses a target in another tenant — lookup is tenant-scoped (B-TEN-1)")
    void setAdminRole_crossTenantTargetIsHidden() {
        when(tenantAccessor.requireTenantId()).thenReturn(7L);
        // The target lives in another tenant, so the tenant-scoped lookup misses.
        when(userRepo.findByIdAndTenantId(999L, 7L)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> admin.setAdminRole(999L,
                tech.cwvermaak.weldforge.model.AdminRole.SUPER_ADMIN))
                .isInstanceOf(EntityNotFoundException.class);

        // No privilege was granted and nothing was audited as a grant.
        verify(userRepo, never()).save(any());
        verify(auditService, never()).recordAdmin(eq("admin.role.assigned"), any(), any(), any(), any());
        // It must NOT fall back to an unscoped lookup.
        verify(userRepo, never()).findById(any());
    }

    @Test
    @DisplayName("setAdminRole requires SUPER_ADMIN — a lesser caller is rejected before any mutation")
    void setAdminRole_nonSuperAdmin_denied() {
        doThrow(new org.springframework.security.access.AccessDeniedException("not super admin"))
                .when(tenantAccessor).requireSuperAdmin();

        assertThatThrownBy(() -> admin.setAdminRole(42L,
                tech.cwvermaak.weldforge.model.AdminRole.TENANT_ADMIN))
                .isInstanceOf(org.springframework.security.access.AccessDeniedException.class);

        verify(userRepo, never()).findByIdAndTenantId(any(), any());
        verify(userRepo, never()).findById(any());
        verify(userRepo, never()).save(any());
    }

    @Test
    @DisplayName("setAdminRole rejects a null role before touching the repository")
    void setAdminRole_nullRole_rejected() {
        assertThatThrownBy(() -> admin.setAdminRole(42L, null))
                .isInstanceOf(IllegalArgumentException.class);

        verify(userRepo, never()).save(any());
    }
}
