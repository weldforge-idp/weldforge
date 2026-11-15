package tech.cwvermaak.weldforge.config;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;
import tech.cwvermaak.weldforge.model.AdminRole;
import tech.cwvermaak.weldforge.model.Tenant;
import tech.cwvermaak.weldforge.model.User;
import tech.cwvermaak.weldforge.repository.UserRepository;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.*;

/**
 * First-run bootstrap. Nothing seeds an admin on a fresh install, so this is
 * the supported way to get the first super admin — which means a promotion
 * that does not actually grant authority leaves an installation with no way in
 * except a manual database edit.
 */
class SuperAdminBootstrapTest {

    private UserRepository users;
    private tech.cwvermaak.weldforge.repository.AdminMembershipRepository memberships;
    private SuperAdminBootstrap bootstrap;
    private User alice;

    @BeforeEach
    void setUp() {
        users = mock(UserRepository.class);
        memberships = mock(tech.cwvermaak.weldforge.repository.AdminMembershipRepository.class);
        when(memberships.findByUser_Id(anyLong())).thenReturn(java.util.List.of());
        bootstrap = new SuperAdminBootstrap(users,
                new tech.cwvermaak.weldforge.config.tenant.GlobalSuperAdminMembership(memberships));

        Tenant t = Tenant.builder().id(1L).slug("acme").name("Acme").build();
        alice = User.builder().id(42L).tenant(t).email("alice@acme.test")
                .adminRole(AdminRole.NONE).build();
        when(users.save(any(User.class))).thenAnswer(inv -> inv.getArgument(0));
    }

    private void runWith(String email) {
        ReflectionTestUtils.setField(bootstrap, "bootstrapEmail", email);
        bootstrap.run(null);
    }

    @Test
    @DisplayName("promotion sets adminRole, which is what authorization actually reads")
    void promotesAdminRoleNotJustTheBoolean() {
        when(users.findAllByEmailIgnoreCase("alice@acme.test")).thenReturn(java.util.List.of(alice));

        runWith("alice@acme.test");

        // The legacy boolean alone leaves the JWT adm claim at NONE, and every
        // super-admin endpoint answers 403.
        assertThat(alice.getAdminRole()).isEqualTo(AdminRole.SUPER_ADMIN);
        assertThat(alice.isSuperAdmin()).isTrue();
        verify(users).save(alice);
    }

    @Test
    @DisplayName("tokens issued before promotion are invalidated")
    void bumpsTokenVersion() {
        alice.setTokenVersion(3);
        when(users.findAllByEmailIgnoreCase(anyString())).thenReturn(java.util.List.of(alice));

        runWith("alice@acme.test");

        assertThat(alice.getTokenVersion()).isEqualTo(4);
    }

    @Test
    @DisplayName("an already-promoted user with a global membership is left alone")
    void isIdempotent() {
        alice.setSuperAdmin(true);
        alice.setAdminRole(AdminRole.SUPER_ADMIN);
        alice.setTokenVersion(7);
        when(users.findAllByEmailIgnoreCase(anyString())).thenReturn(java.util.List.of(alice));
        when(memberships.findByUser_Id(42L)).thenReturn(java.util.List.of(
                tech.cwvermaak.weldforge.model.AdminMembership.builder()
                        .user(alice).tenant(null).adminRole(AdminRole.SUPER_ADMIN).build()));

        runWith("alice@acme.test");

        assertThat(alice.getTokenVersion()).isEqualTo(7);
        verify(users, never()).save(any());
        verify(memberships, never()).save(any());
    }

    @Test
    @DisplayName("promotion grants the global membership that cross-tenant reach is decided by")
    void grantsGlobalMembership() {
        when(users.findAllByEmailIgnoreCase(anyString())).thenReturn(java.util.List.of(alice));

        runWith("alice@acme.test");

        verify(memberships).save(argThat(m -> m.getUser() == alice
                && m.getTenant() == null && m.getAdminRole() == AdminRole.SUPER_ADMIN));
    }

    @Test
    @DisplayName("a super admin promoted before memberships existed gets the missing row, and nothing else changes")
    void repairsMissingMembership() {
        // Production on 2026-09-11: flags set, zero membership rows, so every
        // cross-tenant switch was refused and the portal fell back silently.
        alice.setSuperAdmin(true);
        alice.setAdminRole(AdminRole.SUPER_ADMIN);
        alice.setTokenVersion(7);
        when(users.findAllByEmailIgnoreCase(anyString())).thenReturn(java.util.List.of(alice));

        runWith("alice@acme.test");

        verify(memberships).save(argThat(m -> m.getTenant() == null
                && m.getAdminRole() == AdminRole.SUPER_ADMIN));
        assertThat(alice.getTokenVersion()).isEqualTo(7);
        verify(users, never()).save(any());
    }

    @Test
    @DisplayName("a user promoted only by the old boolean is repaired on next start")
    void repairsHalfPromotedUser() {
        alice.setSuperAdmin(true);
        alice.setAdminRole(AdminRole.NONE);
        when(users.findAllByEmailIgnoreCase(anyString())).thenReturn(java.util.List.of(alice));

        runWith("alice@acme.test");

        assertThat(alice.getAdminRole()).isEqualTo(AdminRole.SUPER_ADMIN);
        verify(users).save(alice);
    }

    @Test
    @DisplayName("no email configured means no lookup at all")
    void doesNothingWhenUnset() {
        runWith("");
        runWith(null);

        verifyNoInteractions(users);
        verifyNoInteractions(memberships);
    }

    // ---- Who gets promoted -------------------------------------------------
    //
    // An address is unique only per tenant. The lookup used to be
    // findFirstByEmailIgnoreCase -- no tenant, no order, no verification -- so
    // anyone who registered the bootstrap address in a tenant with sign-up
    // open had a row that a later restart could promote to super admin.

    private User someoneElseWithTheSameAddress() {
        Tenant other = Tenant.builder().id(2L).slug("open-signup").name("Open").build();
        return User.builder().id(99L).tenant(other).email("alice@acme.test")
                .adminRole(AdminRole.NONE).build();
    }

    private void runWith(String email, String tenant) {
        ReflectionTestUtils.setField(bootstrap, "bootstrapTenant", tenant);
        runWith(email);
    }

    @Test
    @DisplayName("an address held in two tenants promotes nobody when no tenant is named")
    void ambiguousAddressPromotesNobody() {
        User other = someoneElseWithTheSameAddress();
        when(users.findAllByEmailIgnoreCase("alice@acme.test")).thenReturn(java.util.List.of(alice, other));

        runWith("alice@acme.test");

        assertThat(alice.getAdminRole()).isEqualTo(AdminRole.NONE);
        assertThat(other.getAdminRole()).isEqualTo(AdminRole.NONE);
        verify(users, never()).save(any());
        verify(memberships, never()).save(any());
    }

    @Test
    @DisplayName("naming the tenant promotes the account there and ignores the same address elsewhere")
    void tenantScopedLookup() {
        alice.setEmailVerified(true);
        when(users.findByTenant_SlugAndEmailIgnoreCase("acme", "alice@acme.test")).thenReturn(Optional.of(alice));

        runWith("alice@acme.test", "acme");

        assertThat(alice.getAdminRole()).isEqualTo(AdminRole.SUPER_ADMIN);
        // The cross-tenant lookup is never consulted, so a row registered in
        // another tenant cannot be the one chosen.
        verify(users, never()).findAllByEmailIgnoreCase(anyString());
    }

    @Test
    @DisplayName("naming a tenant where the address does not exist promotes nobody")
    void tenantScopedNoMatch() {
        when(users.findByTenant_SlugAndEmailIgnoreCase(anyString(), anyString())).thenReturn(Optional.empty());

        runWith("alice@acme.test", "acme");

        verify(users, never()).save(any());
        verify(users, never()).findAllByEmailIgnoreCase(anyString());
    }

    @Test
    @DisplayName("once a super admin exists, an unverified address is not promoted")
    void unverifiedRefusedWhenSuperAdminExists() {
        when(users.findAllByEmailIgnoreCase(anyString())).thenReturn(java.util.List.of(alice));
        when(users.existsByAdminRole(AdminRole.SUPER_ADMIN)).thenReturn(true);

        runWith("alice@acme.test");

        assertThat(alice.getAdminRole()).isEqualTo(AdminRole.NONE);
        verify(users, never()).save(any());
        verify(memberships, never()).save(any());
    }

    @Test
    @DisplayName("once a super admin exists, a verified address is still promoted (lockout recovery)")
    void verifiedPromotedWhenSuperAdminExists() {
        alice.setEmailVerified(true);
        when(users.findAllByEmailIgnoreCase(anyString())).thenReturn(java.util.List.of(alice));
        when(users.existsByAdminRole(AdminRole.SUPER_ADMIN)).thenReturn(true);

        runWith("alice@acme.test");

        assertThat(alice.getAdminRole()).isEqualTo(AdminRole.SUPER_ADMIN);
        verify(users).save(alice);
    }

    @Test
    @DisplayName("a fresh install with no super admin promotes the first account unverified")
    void firstRunNeedsNoVerification() {
        when(users.findAllByEmailIgnoreCase(anyString())).thenReturn(java.util.List.of(alice));
        when(users.existsByAdminRole(AdminRole.SUPER_ADMIN)).thenReturn(false);

        runWith("alice@acme.test");

        assertThat(alice.getAdminRole()).isEqualTo(AdminRole.SUPER_ADMIN);
    }

    @Test
    @DisplayName("an unknown email promotes nobody")
    void unknownEmailIsANoOp() {
        when(users.findAllByEmailIgnoreCase(anyString())).thenReturn(java.util.List.of());

        runWith("nobody@acme.test");

        verify(users, never()).save(any());
    }
}
