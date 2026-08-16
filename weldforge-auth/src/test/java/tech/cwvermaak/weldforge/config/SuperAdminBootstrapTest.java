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
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

/**
 * First-run bootstrap. Nothing seeds an admin on a fresh install, so this is
 * the supported way to get the first super admin — which means a promotion
 * that does not actually grant authority leaves an installation with no way in
 * except a manual database edit.
 */
class SuperAdminBootstrapTest {

    private UserRepository users;
    private SuperAdminBootstrap bootstrap;
    private User alice;

    @BeforeEach
    void setUp() {
        users = mock(UserRepository.class);
        bootstrap = new SuperAdminBootstrap(users);

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
        when(users.findFirstByEmailIgnoreCase("alice@acme.test")).thenReturn(Optional.of(alice));

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
        when(users.findFirstByEmailIgnoreCase(anyString())).thenReturn(Optional.of(alice));

        runWith("alice@acme.test");

        assertThat(alice.getTokenVersion()).isEqualTo(4);
    }

    @Test
    @DisplayName("an already-promoted user is left alone")
    void isIdempotent() {
        alice.setSuperAdmin(true);
        alice.setAdminRole(AdminRole.SUPER_ADMIN);
        alice.setTokenVersion(7);
        when(users.findFirstByEmailIgnoreCase(anyString())).thenReturn(Optional.of(alice));

        runWith("alice@acme.test");

        assertThat(alice.getTokenVersion()).isEqualTo(7);
        verify(users, never()).save(any());
    }

    @Test
    @DisplayName("a user promoted only by the old boolean is repaired on next start")
    void repairsHalfPromotedUser() {
        alice.setSuperAdmin(true);
        alice.setAdminRole(AdminRole.NONE);
        when(users.findFirstByEmailIgnoreCase(anyString())).thenReturn(Optional.of(alice));

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
    }

    @Test
    @DisplayName("an unknown email promotes nobody")
    void unknownEmailIsANoOp() {
        when(users.findFirstByEmailIgnoreCase(anyString())).thenReturn(Optional.empty());

        runWith("nobody@acme.test");

        verify(users, never()).save(any());
    }
}
