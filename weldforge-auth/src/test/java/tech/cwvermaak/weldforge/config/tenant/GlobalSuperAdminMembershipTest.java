package tech.cwvermaak.weldforge.config.tenant;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import tech.cwvermaak.weldforge.model.AdminMembership;
import tech.cwvermaak.weldforge.model.AdminRole;
import tech.cwvermaak.weldforge.model.Tenant;
import tech.cwvermaak.weldforge.model.User;
import tech.cwvermaak.weldforge.repository.AdminMembershipRepository;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.*;

/**
 * The one place a super-admin's cross-tenant reach is granted or removed.
 * Its flag rule must match the portal's (sa OR adm=SUPER_ADMIN) and V57's,
 * or the portal offers a tenant picker the backend refuses.
 */
class GlobalSuperAdminMembershipTest {

    private AdminMembershipRepository repo;
    private GlobalSuperAdminMembership global;
    private final Tenant acme = Tenant.builder().id(7L).slug("acme").build();

    @BeforeEach
    void setUp() {
        repo = mock(AdminMembershipRepository.class);
        when(repo.findByUser_Id(anyLong())).thenReturn(List.of());
        global = new GlobalSuperAdminMembership(repo);
    }

    private static User user(boolean sa, AdminRole role) {
        return User.builder().id(42L).email("a@x.test").superAdmin(sa).adminRole(role).build();
    }

    @Test
    @DisplayName("the flag rule is sa OR adm=SUPER_ADMIN -- the same one the portal uses")
    void flagRuleMatchesPortal() {
        assertThat(GlobalSuperAdminMembership.flaggedSuperAdmin(user(true, AdminRole.SUPER_ADMIN))).isTrue();
        assertThat(GlobalSuperAdminMembership.flaggedSuperAdmin(user(true, AdminRole.NONE))).isTrue();
        assertThat(GlobalSuperAdminMembership.flaggedSuperAdmin(user(false, AdminRole.SUPER_ADMIN))).isTrue();
        assertThat(GlobalSuperAdminMembership.flaggedSuperAdmin(user(false, AdminRole.TENANT_ADMIN))).isFalse();
        assertThat(GlobalSuperAdminMembership.flaggedSuperAdmin(user(false, AdminRole.NONE))).isFalse();
    }

    @Test
    @DisplayName("sync grants a global SUPER_ADMIN row to a flagged super-admin, recording the grantor")
    void syncGrants() {
        User u = user(true, AdminRole.SUPER_ADMIN);

        global.sync(u, 1L);

        verify(repo).save(argThat(m -> m.getUser() == u && m.getTenant() == null
                && m.getAdminRole() == AdminRole.SUPER_ADMIN && Long.valueOf(1L).equals(m.getGrantedBy())));
    }

    @Test
    @DisplayName("grant is idempotent")
    void grantIdempotent() {
        User u = user(true, AdminRole.SUPER_ADMIN);
        when(repo.findByUser_Id(42L)).thenReturn(List.of(
                AdminMembership.builder().id(5L).user(u).tenant(null).adminRole(AdminRole.SUPER_ADMIN).build()));

        assertThat(global.grant(u, null)).isFalse();
        verify(repo, never()).save(any());
    }

    @Test
    @DisplayName("sync on demotion removes the global row and leaves per-tenant memberships alone")
    void syncRevokesOnlyGlobal() {
        User u = user(false, AdminRole.TENANT_ADMIN);
        AdminMembership globalRow = AdminMembership.builder()
                .id(5L).user(u).tenant(null).adminRole(AdminRole.SUPER_ADMIN).build();
        AdminMembership tenantRow = AdminMembership.builder()
                .id(6L).user(u).tenant(acme).adminRole(AdminRole.TENANT_ADMIN).build();
        when(repo.findByUser_Id(42L)).thenReturn(List.of(globalRow, tenantRow));

        global.sync(u, 1L);

        verify(repo).deleteAll(List.of(globalRow));
        verify(repo, never()).save(any());
    }

    @Test
    @DisplayName("a user never persisted has no memberships to look up")
    void unsavedUser() {
        User u = User.builder().email("new@x.test").superAdmin(false).adminRole(AdminRole.NONE).build();

        assertThat(global.revoke(u)).isZero();
        verifyNoInteractions(repo);
    }
}
