package tech.cwvermaak.weldforge.config.tenant;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.access.AccessDeniedException;
import tech.cwvermaak.weldforge.model.AdminMembership;
import tech.cwvermaak.weldforge.model.AdminRole;
import tech.cwvermaak.weldforge.model.Tenant;
import tech.cwvermaak.weldforge.model.User;
import tech.cwvermaak.weldforge.repository.AdminMembershipRepository;
import tech.cwvermaak.weldforge.repository.TenantRepository;

import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.*;

/**
 * Cross-tenant authorization core — {@code effectiveRole} and
 * {@code switchToTenant} (cross-tenant-admin-spec.md §5/§6.1).
 */
class TenantAccessorTest {

    private static final long HOME = 1L;
    private static final long OTHER = 10L;

    private TenantRepository tenantRepository;
    private AdminMembershipRepository membershipRepository;
    private TenantAccessor accessor;

    @BeforeEach
    void setUp() {
        tenantRepository = mock(TenantRepository.class);
        membershipRepository = mock(AdminMembershipRepository.class);
        accessor = new TenantAccessor(tenantRepository, membershipRepository);
    }

    @AfterEach
    void tearDown() {
        TenantContext.clear();
    }

    private static Tenant tenant(long id, String slug) {
        return Tenant.builder().id(id).slug(slug).name(slug).build();
    }

    private AdminMembership membership(Tenant tenant, AdminRole role) {
        return AdminMembership.builder()
                .user(User.builder().id(99L).build())
                .tenant(tenant)            // null == global
                .adminRole(role)
                .build();
    }

    // ---- user effective role ----------------------------------------

    @Test
    @DisplayName("a user keeps their resolved role for their own home tenant")
    void user_homeTenant_usesResolvedRole() {
        TenantContext.set("home", HOME, AdminRole.TENANT_ADMIN);
        TenantContext.setActorUser(99L);
        when(membershipRepository.findByUser_Id(99L)).thenReturn(List.of());

        assertThat(accessor.effectiveRole(HOME)).isEqualTo(AdminRole.TENANT_ADMIN);
        // No reach into another tenant without a membership.
        assertThat(accessor.effectiveRole(OTHER)).isEqualTo(AdminRole.NONE);
    }

    @Test
    @DisplayName("a global membership applies to every tenant, SUPER_ADMIN included")
    void user_globalMembership_appliesEverywhere() {
        TenantContext.set("home", HOME, AdminRole.NONE);
        TenantContext.setActorUser(99L);
        when(membershipRepository.findByUser_Id(99L))
                .thenReturn(List.of(membership(null, AdminRole.SUPER_ADMIN)));

        assertThat(accessor.effectiveRole(OTHER)).isEqualTo(AdminRole.SUPER_ADMIN);
        assertThat(accessor.effectiveRole(777L)).isEqualTo(AdminRole.SUPER_ADMIN);
    }

    @Test
    @DisplayName("a per-tenant membership only grants reach into that one tenant")
    void user_perTenantMembership_isScoped() {
        TenantContext.set("home", HOME, AdminRole.NONE);
        TenantContext.setActorUser(99L);
        when(membershipRepository.findByUser_Id(99L))
                .thenReturn(List.of(membership(tenant(OTHER, "other"), AdminRole.TENANT_ADMIN)));

        assertThat(accessor.effectiveRole(OTHER)).isEqualTo(AdminRole.TENANT_ADMIN);
        assertThat(accessor.effectiveRole(778L)).isEqualTo(AdminRole.NONE);
    }

    @Test
    @DisplayName("a per-tenant SUPER_ADMIN grant is downgraded to TENANT_ADMIN (spec §5)")
    void user_perTenantSuperAdmin_isDowngraded() {
        TenantContext.set("home", HOME, AdminRole.NONE);
        TenantContext.setActorUser(99L);
        when(membershipRepository.findByUser_Id(99L))
                .thenReturn(List.of(membership(tenant(OTHER, "other"), AdminRole.SUPER_ADMIN)));

        assertThat(accessor.effectiveRole(OTHER)).isEqualTo(AdminRole.TENANT_ADMIN);
    }

    // ---- service-account effective role -----------------------------

    @Test
    @DisplayName("a SUPER_ADMIN service account reaches every tenant")
    void serviceAccount_superAdmin_isGlobal() {
        TenantContext.set("home", HOME, AdminRole.SUPER_ADMIN);
        TenantContext.setActorServiceAccount(5L);

        assertThat(accessor.effectiveRole(OTHER)).isEqualTo(AdminRole.SUPER_ADMIN);
        verifyNoInteractions(membershipRepository);
    }

    @Test
    @DisplayName("a non-super service account is confined to its home tenant")
    void serviceAccount_tenantAdmin_isHomeOnly() {
        TenantContext.set("home", HOME, AdminRole.TENANT_ADMIN);
        TenantContext.setActorServiceAccount(5L);

        assertThat(accessor.effectiveRole(HOME)).isEqualTo(AdminRole.TENANT_ADMIN);
        assertThat(accessor.effectiveRole(OTHER)).isEqualTo(AdminRole.NONE);
    }

    // ---- switchToTenant ---------------------------------------------

    @Test
    @DisplayName("switchToTenant rebinds the context when the caller has reach")
    void switchToTenant_grantsAndRebinds() {
        TenantContext.set("home", HOME, AdminRole.SUPER_ADMIN);
        TenantContext.setActorServiceAccount(5L);
        when(tenantRepository.findBySlug("other")).thenReturn(Optional.of(tenant(OTHER, "other")));

        AdminRole role = accessor.switchToTenant("other");

        assertThat(role).isEqualTo(AdminRole.SUPER_ADMIN);
        assertThat(TenantContext.getTenantId()).isEqualTo(OTHER);
        assertThat(TenantContext.getAdminRole()).isEqualTo(AdminRole.SUPER_ADMIN);
        // Actor identity survives the context switch.
        assertThat(TenantContext.getActorServiceAccountId()).isEqualTo(5L);
    }

    @Test
    @DisplayName("switchToTenant rejects a caller with no admin reach into the target")
    void switchToTenant_deniesWithoutReach() {
        TenantContext.set("home", HOME, AdminRole.TENANT_ADMIN);
        TenantContext.setActorUser(99L);
        when(tenantRepository.findBySlug("other")).thenReturn(Optional.of(tenant(OTHER, "other")));
        when(membershipRepository.findByUser_Id(99L)).thenReturn(List.of());

        assertThatThrownBy(() -> accessor.switchToTenant("other"))
                .isInstanceOf(AccessDeniedException.class);
    }
}
