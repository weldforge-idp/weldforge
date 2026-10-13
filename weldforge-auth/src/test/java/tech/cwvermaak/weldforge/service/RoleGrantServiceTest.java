package tech.cwvermaak.weldforge.service;

import jakarta.persistence.EntityNotFoundException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.security.access.AccessDeniedException;

import tech.cwvermaak.weldforge.config.tenant.TenantContext;
import tech.cwvermaak.weldforge.model.AdminRole;
import tech.cwvermaak.weldforge.model.Role;
import tech.cwvermaak.weldforge.model.ServiceAccount;
import tech.cwvermaak.weldforge.model.Tenant;
import tech.cwvermaak.weldforge.model.User;
import tech.cwvermaak.weldforge.model.dto.RoleGrantDto;
import tech.cwvermaak.weldforge.repository.RoleRepository;
import tech.cwvermaak.weldforge.repository.ServiceAccountRepository;
import tech.cwvermaak.weldforge.repository.UserRepository;
import tech.cwvermaak.weldforge.service.audit.AuditEventTypes;
import tech.cwvermaak.weldforge.service.audit.AuditService;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

/**
 * A credential that may assign roles under one prefix and do nothing else.
 *
 * <p>The property worth protecting is in {@link Replace#leavesEverythingElseAlone()}:
 * a replace carries roles outside the prefix through untouched. Everything
 * else here guards the ways that could stop being true.
 */
@DisplayName("RoleGrantService")
class RoleGrantServiceTest {

    private static final long TENANT_ID = 1L;
    private static final long OTHER_TENANT_ID = 2L;
    private static final long SA_ID = 77L;
    private static final long USER_ID = 42L;
    private static final String PREFIX = "clepsydra:";

    private ServiceAccountRepository serviceAccounts;
    private UserRepository users;
    private RoleRepository roles;
    private AuditService audit;
    private RoleGrantService service;

    private Tenant tenant;
    private User target;

    @BeforeEach
    void setUp() {
        serviceAccounts = mock(ServiceAccountRepository.class);
        users = mock(UserRepository.class);
        roles = mock(RoleRepository.class);
        audit = mock(AuditService.class);
        service = new RoleGrantService(serviceAccounts, users, roles, audit);

        tenant = Tenant.builder().id(TENANT_ID).slug("cwvermaak-tech").name("CWVermaak").build();
        target = User.builder().id(USER_ID).tenant(tenant).email("sipho@cwvermaak.test").build();

        signedInAs(serviceAccount(PREFIX, true, null));
        when(users.findByIdAndTenantId(USER_ID, TENANT_ID)).thenReturn(Optional.of(target));
        when(users.save(any())).thenAnswer(inv -> inv.getArgument(0));
        when(roles.save(any())).thenAnswer(inv -> {
            Role r = inv.getArgument(0);
            if (r.getId() == null) r.setId(900L + r.getName().hashCode() % 100);
            return r;
        });
    }

    @AfterEach
    void tearDown() {
        TenantContext.clear();
    }

    // ------------------------------------------------------------- fixtures

    private ServiceAccount serviceAccount(String prefix, boolean enabled, LocalDateTime expiresAt) {
        return ServiceAccount.builder()
                .id(SA_ID).tenant(tenant).name("clepsydra")
                .tokenPrefix("wf_svc_ab").tokenHash("h")
                .adminRole(AdminRole.NONE)
                .roleGrantPrefix(prefix)
                .enabled(enabled)
                .expiresAt(expiresAt)
                .build();
    }

    private void signedInAs(ServiceAccount sa) {
        TenantContext.clear();
        TenantContext.set(tenant.getSlug(), TENANT_ID, AdminRole.NONE);
        TenantContext.setActorServiceAccount(sa.getId());
        when(serviceAccounts.findById(sa.getId())).thenReturn(Optional.of(sa));
    }

    private static Role role(long id, Tenant t, String name) {
        return Role.builder().id(id).tenant(t).name(name).build();
    }

    /** What the user currently holds. */
    private void holding(Role... held) {
        when(roles.findRolesByUserId(USER_ID)).thenReturn(new ArrayList<>(List.of(held)));
    }

    /** A role that already exists in the tenant, found by name. */
    private void existing(Role r) {
        when(roles.findByTenantIdAndNameIgnoreCase(TENANT_ID, r.getName())).thenReturn(Optional.of(r));
    }

    private void noSuchRole(String name) {
        when(roles.findByTenantIdAndNameIgnoreCase(TENANT_ID, name)).thenReturn(Optional.empty());
    }

    // ---------------------------------------------------------------- guard

    @Nested
    @DisplayName("who may call this at all")
    class Guard {

        @Test
        @DisplayName("a caller that is not a service account is refused")
        void noServiceAccount() {
            TenantContext.clear();
            TenantContext.set("cwvermaak-tech", TENANT_ID, AdminRole.SUPER_ADMIN);

            // Deliberate: a super admin is refused too. They already have
            // PUT /api/admin/users/{id}/roles, and a second writer of the same
            // rows is a second thing to keep correct.
            assertThatThrownBy(() -> service.list(USER_ID))
                    .isInstanceOf(AccessDeniedException.class);
        }

        @Test
        @DisplayName("a service account without a prefix is refused")
        void noPrefix() {
            signedInAs(serviceAccount(null, true, null));
            assertThatThrownBy(() -> service.list(USER_ID))
                    .isInstanceOf(AccessDeniedException.class)
                    .hasMessageContaining("no role grant prefix");
        }

        @Test
        @DisplayName("a blank prefix is not a capability")
        void blankPrefix() {
            signedInAs(serviceAccount("   ", true, null));
            assertThatThrownBy(() -> service.list(USER_ID))
                    .isInstanceOf(AccessDeniedException.class);
        }

        @Test
        @DisplayName("a disabled account is refused")
        void disabled() {
            signedInAs(serviceAccount(PREFIX, false, null));
            assertThatThrownBy(() -> service.list(USER_ID))
                    .isInstanceOf(AccessDeniedException.class)
                    .hasMessageContaining("disabled");
        }

        @Test
        @DisplayName("an expired account is refused even though the filter also checks")
        void expired() {
            signedInAs(serviceAccount(PREFIX, true, LocalDateTime.now().minusDays(1)));
            assertThatThrownBy(() -> service.list(USER_ID))
                    .isInstanceOf(AccessDeniedException.class)
                    .hasMessageContaining("expired");
        }

        @Test
        @DisplayName("a user in another tenant is not found, not forbidden")
        void otherTenantUser() {
            when(users.findByIdAndTenantId(99L, TENANT_ID)).thenReturn(Optional.empty());
            // 404 rather than 403 on purpose: the caller must not learn which
            // tenant an id lives in.
            assertThatThrownBy(() -> service.list(99L))
                    .isInstanceOf(EntityNotFoundException.class);
        }
    }

    // ----------------------------------------------------------------- read

    @Nested
    @DisplayName("reading")
    class Read {

        @Test
        @DisplayName("shows only the roles under the prefix")
        void onlyUnderPrefix() {
            holding(role(1, tenant, "clepsydra:member"),
                    role(2, tenant, "staff"),
                    role(3, tenant, "leap:admin"));

            RoleGrantDto out = service.list(USER_ID);

            assertThat(out.getRoles()).containsExactly("clepsydra:member");
            assertThat(out.getUserId()).isEqualTo(USER_ID);
            assertThat(out.getPrefix()).isEqualTo(PREFIX);
        }

        @Test
        @DisplayName("a user with none of them reads back empty, not an error")
        void none() {
            holding(role(2, tenant, "staff"));
            assertThat(service.list(USER_ID).getRoles()).isEmpty();
        }

        @Test
        @DisplayName("a read writes no audit row")
        void notAudited() {
            holding(role(1, tenant, "clepsydra:member"));
            service.list(USER_ID);
            verifyNoInteractions(audit);
        }
    }

    // ---------------------------------------------------------------- write

    @Nested
    @DisplayName("replacing")
    class Replace {

        /** The property the whole feature exists to provide. */
        @Test
        @DisplayName("leaves every role outside the prefix exactly as it was")
        void leavesEverythingElseAlone() {
            Role member = role(1, tenant, "clepsydra:member");
            Role staff = role(2, tenant, "staff");
            Role leap = role(3, tenant, "leap:admin");
            holding(member, staff, leap);
            existing(member);
            Role pm = role(4, tenant, "clepsydra:pm");
            existing(pm);

            service.replace(USER_ID, List.of("clepsydra:member", "clepsydra:pm"));

            assertThat(target.getRoles()).extracting(Role::getName)
                    .containsExactlyInAnyOrder("staff", "leap:admin",
                            "clepsydra:member", "clepsydra:pm");
        }

        @Test
        @DisplayName("an empty list clears the namespace and nothing else")
        void emptyClearsOnlyThePrefix() {
            holding(role(1, tenant, "clepsydra:member"),
                    role(2, tenant, "staff"));

            RoleGrantDto out = service.replace(USER_ID, List.of());

            assertThat(target.getRoles()).extracting(Role::getName).containsExactly("staff");
            assertThat(out.getRoles()).isEmpty();
        }

        @Test
        @DisplayName("a name outside the prefix refuses the whole call and writes nothing")
        void nameOutsidePrefix() {
            holding(role(2, tenant, "staff"));

            assertThatThrownBy(() -> service.replace(USER_ID,
                    List.of("clepsydra:member", "tenant-admin")))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("tenant-admin")
                    .hasMessageContaining("not under this account's prefix");

            // Not "the valid ones were applied": nothing was.
            verify(users, never()).save(any());
            verify(roles, never()).save(any());
        }

        @Test
        @DisplayName("a refusal is audited, because a call that writes nothing leaves no other trace")
        void refusalIsAudited() {
            holding(role(2, tenant, "staff"));

            assertThatThrownBy(() -> service.replace(USER_ID, List.of("staff")))
                    .isInstanceOf(IllegalArgumentException.class);

            verify(audit).recordAdmin(eq(AuditEventTypes.ROLE_GRANT_REFUSED), any(),
                    anyString(), anyString(), any());
        }

        @Test
        @DisplayName("a blank name is refused rather than silently dropped")
        void blankName() {
            holding();
            assertThatThrownBy(() -> service.replace(USER_ID, List.of("clepsydra:member", "  ")))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("may not be blank");
        }

        @Test
        @DisplayName("a missing role is created, and the response says which")
        void createsMissing() {
            holding();
            Role member = role(1, tenant, "clepsydra:member");
            existing(member);
            noSuchRole("clepsydra:pm");

            RoleGrantDto out = service.replace(USER_ID, List.of("clepsydra:member", "clepsydra:pm"));

            assertThat(out.getCreated()).containsExactly("clepsydra:pm");
            assertThat(out.getRoles()).containsExactly("clepsydra:member", "clepsydra:pm");
            verify(audit).recordAdmin(eq(AuditEventTypes.ROLE_GRANT_ROLE_CREATED), any(),
                    anyString(), eq("clepsydra:pm"), any());
        }

        @Test
        @DisplayName("creating nothing reports nothing, so a caller can assert on it")
        void createsNothing() {
            holding();
            existing(role(1, tenant, "clepsydra:member"));

            assertThat(service.replace(USER_ID, List.of("clepsydra:member")).getCreated()).isEmpty();
        }

        /**
         * The reason the prefix match is case-insensitive. Role names are
         * already unique without regard to case, so a case-sensitive filter
         * would leave this role inside the namespace, invisible to a listing
         * of it and impossible to remove through the API that owns it.
         */
        @Test
        @DisplayName("a role stored in another case is still inside the namespace and can be removed")
        void caseInsensitivePrefix() {
            Role oddCase = role(1, tenant, "Clepsydra:Member");
            holding(oddCase, role(2, tenant, "staff"));

            assertThat(service.list(USER_ID).getRoles()).containsExactly("Clepsydra:Member");

            service.replace(USER_ID, List.of());

            assertThat(target.getRoles()).extracting(Role::getName).containsExactly("staff");
        }

        @Test
        @DisplayName("the resulting set is ordered by name, so the roles claim is stable")
        void ordered() {
            holding();
            existing(role(1, tenant, "clepsydra:zeta"));
            existing(role(2, tenant, "clepsydra:alpha"));

            RoleGrantDto out = service.replace(USER_ID, List.of("clepsydra:zeta", "clepsydra:alpha"));

            assertThat(out.getRoles()).containsExactly("clepsydra:alpha", "clepsydra:zeta");
        }

        @Test
        @DisplayName("token_version is bumped, matching AdminService.setUserRoles")
        void bumpsTokenVersion() {
            holding();
            existing(role(1, tenant, "clepsydra:member"));
            int before = target.getTokenVersion();

            service.replace(USER_ID, List.of("clepsydra:member"));

            assertThat(target.getTokenVersion()).isEqualTo(before + 1);
        }

        @Test
        @DisplayName("the success is audited with the service account named")
        void auditsSuccess() {
            holding();
            existing(role(1, tenant, "clepsydra:member"));

            service.replace(USER_ID, List.of("clepsydra:member"));

            verify(audit).recordAdmin(eq(AuditEventTypes.ROLE_GRANT_REPLACED), any(),
                    eq(AuditEventTypes.TARGET_USER), eq(String.valueOf(USER_ID)), any());
        }

        @Test
        @DisplayName("a duplicate name in the request is not a duplicate role")
        void duplicates() {
            holding();
            existing(role(1, tenant, "clepsydra:member"));

            RoleGrantDto out = service.replace(USER_ID,
                    List.of("clepsydra:member", "clepsydra:member"));

            assertThat(out.getRoles()).containsExactly("clepsydra:member");
        }
    }

    // --------------------------------------------------------------- prefix

    @Nested
    @DisplayName("the prefix itself")
    class PrefixValidation {

        @Test
        @DisplayName("a normal namespace is accepted and trimmed")
        void accepted() {
            assertThat(RoleGrantService.validatePrefix("  clepsydra:  ")).isEqualTo("clepsydra:");
            assertThat(RoleGrantService.validatePrefix("acme-")).isEqualTo("acme-");
        }

        @Test
        @DisplayName("null and blank mean no capability rather than an error")
        void cleared() {
            assertThat(RoleGrantService.validatePrefix(null)).isNull();
            assertThat(RoleGrantService.validatePrefix("   ")).isNull();
        }

        /**
         * A one-character prefix matches by coincidence rather than naming a
         * namespace: "c" covers clepsydra:member and customer-support alike.
         */
        @Test
        @DisplayName("one character is refused")
        void tooShort() {
            assertThatThrownBy(() -> RoleGrantService.validatePrefix("c"))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("at least 2");
        }

        @Test
        @DisplayName("longer than the column is refused")
        void tooLong() {
            assertThatThrownBy(() -> RoleGrantService.validatePrefix("x".repeat(65)))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("at most 64");
        }

        @Test
        @DisplayName("whitespace inside is refused")
        void whitespace() {
            assertThatThrownBy(() -> RoleGrantService.validatePrefix("cle psydra:"))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("whitespace");
        }

        @Test
        @DisplayName("the delimiter is a convention, not a rule")
        void noDelimiterRequired() {
            // A tenant that namespaces with '-' or '/' must not be refused.
            assertThatCode(() -> RoleGrantService.validatePrefix("clepsydra"))
                    .doesNotThrowAnyException();
        }
    }
}
