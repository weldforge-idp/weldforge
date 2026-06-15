package tech.cwvermaak.weldforge.bdd;

import io.cucumber.java.en.Given;
import io.cucumber.java.en.Then;
import io.cucumber.java.en.When;
import jakarta.persistence.EntityNotFoundException;
import tech.cwvermaak.weldforge.config.tenant.TenantAccessor;
import tech.cwvermaak.weldforge.model.Tenant;
import tech.cwvermaak.weldforge.model.User;
import tech.cwvermaak.weldforge.repository.AppClientRepository;
import tech.cwvermaak.weldforge.repository.EnvironmentRepository;
import tech.cwvermaak.weldforge.repository.RoleRepository;
import tech.cwvermaak.weldforge.repository.UserRepository;
import tech.cwvermaak.weldforge.service.AdminService;
import tech.cwvermaak.weldforge.service.audit.AuditService;
import tech.cwvermaak.weldforge.service.mfa.MfaService;

import java.util.Optional;
import java.util.concurrent.atomic.AtomicLong;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.*;

public class TenantIsolationSteps {

    private final TestWorld world;
    private final AtomicLong ids = new AtomicLong(100);

    private TenantAccessor tenantAccessor;
    private RoleRepository roleRepo;
    private UserRepository userRepo;
    private EnvironmentRepository envRepo;
    private AppClientRepository appClientRepo;
    private MfaService mfaService;
    private AuditService auditService;
    private AdminService admin;

    public TenantIsolationSteps(TestWorld world) {
        this.world = world;
    }

    private void ensureAdmin() {
        if (admin != null) return;
        tenantAccessor = mock(TenantAccessor.class);
        roleRepo = mock(RoleRepository.class);
        userRepo = mock(UserRepository.class);
        envRepo = mock(EnvironmentRepository.class);
        appClientRepo = mock(AppClientRepository.class);
        mfaService = mock(MfaService.class);
        auditService = mock(AuditService.class);
        admin = new AdminService(tenantAccessor, roleRepo, userRepo, envRepo,
                appClientRepo, mfaService, auditService,
                mock(tech.cwvermaak.weldforge.service.PasswordResetService.class));
    }

    @Given("tenants {string} and {string} exist")
    public void tenantsExist(String a, String b) {
        world.tenants.put(a, Tenant.builder().id(ids.getAndIncrement()).slug(a).name(a).build());
        world.tenants.put(b, Tenant.builder().id(ids.getAndIncrement()).slug(b).name(b).build());
    }

    @Given("{string} has user {string}")
    public void tenantHasUser(String tenantSlug, String email) {
        Tenant t = world.tenants.get(tenantSlug);
        User u = User.builder().id(ids.getAndIncrement()).tenant(t).email(email).username(email).build();
        world.users.put(email, u);
    }

    @Given("I am authenticated as {string}")
    public void iAmAuthenticatedAs(String email) {
        ensureAdmin();
        User me = world.users.get(email);
        world.currentActor = me;

        // Wire the mocks to simulate tenant scoping: the AdminService only
        // ever sees rows whose tenant matches the caller's tenant.
        Long myTid = me.getTenant().getId();
        when(tenantAccessor.requireTenantId()).thenReturn(myTid);
        when(tenantAccessor.requireTenant()).thenReturn(me.getTenant());

        when(userRepo.findByTenantId(myTid)).thenReturn(
                world.users.values().stream()
                        .filter(u -> u.getTenant().getId().equals(myTid))
                        .toList());

        when(userRepo.findByIdAndTenantId(anyLong(), anyLong())).thenAnswer(inv -> {
            Long id = inv.getArgument(0);
            Long tid = inv.getArgument(1);
            return world.users.values().stream()
                    .filter(u -> u.getId().equals(id) && u.getTenant().getId().equals(tid))
                    .findFirst();
        });

        when(userRepo.findByTenant_SlugAndEmailIgnoreCase(any(), any())).thenAnswer(inv ->
                Optional.ofNullable(world.users.get(inv.getArgument(1))));
    }

    @When("I list users via the admin API")
    public void iListUsersViaAdminApi() {
        world.listedUsers.clear();
        admin.listUsers().forEach(dto ->
                world.users.values().stream()
                        .filter(u -> u.getEmail().equalsIgnoreCase(dto.getEmail()))
                        .findFirst()
                        .ifPresent(world.listedUsers::add));
    }

    @Then("the result contains {string}")
    public void resultContains(String email) {
        assertThat(world.listedUsers).extracting(User::getEmail).contains(email);
    }

    @Then("the result does not contain {string}")
    public void resultDoesNotContain(String email) {
        assertThat(world.listedUsers).extracting(User::getEmail).doesNotContain(email);
    }

    @When("I try to delete the user {string}")
    public void iTryToDelete(String email) {
        User target = world.users.get(email);
        try {
            admin.deleteUser(target.getId());
        } catch (Throwable t) {
            world.lastError = t;
        }
    }

    @When("I try to reset MFA for the user {string}")
    public void iTryToResetMfa(String email) {
        User target = world.users.get(email);
        try {
            world.lastRemoved = admin.resetUserMfa(target.getId());
        } catch (Throwable t) {
            world.lastError = t;
        }
    }

    @Then("the operation is rejected as {string}")
    public void operationRejectedAs(String reason) {
        assertThat(world.lastError).isNotNull();
        if ("not found".equals(reason)) {
            assertThat(world.lastError).isInstanceOf(EntityNotFoundException.class);
        }
    }

    @Then("no MFA factors are removed")
    public void noMfaFactorsRemoved() {
        verify(mfaService, never()).adminReset(any(), any());
        assertThat(world.lastRemoved).isZero();
    }

    // -------- setAdminRole tenant scoping (B-TEN-1) --------------------

    @When("I grant the admin role {string} to user {string}")
    public void iGrantAdminRole(String role, String email) {
        when(userRepo.save(any())).thenAnswer(inv -> inv.getArgument(0));
        User target = world.users.get(email);
        admin.setAdminRole(target.getId(), tech.cwvermaak.weldforge.model.AdminRole.valueOf(role));
    }

    @When("I try to grant the admin role {string} to user {string}")
    public void iTryToGrantAdminRole(String role, String email) {
        User target = world.users.get(email);
        try {
            admin.setAdminRole(target.getId(), tech.cwvermaak.weldforge.model.AdminRole.valueOf(role));
        } catch (Throwable t) {
            world.lastError = t;
        }
    }

    @Then("user {string} has admin role {string}")
    public void userHasAdminRole(String email, String role) {
        User u = world.users.get(email);
        tech.cwvermaak.weldforge.model.AdminRole actual = u.getAdminRole() == null
                ? tech.cwvermaak.weldforge.model.AdminRole.NONE : u.getAdminRole();
        assertThat(actual).isEqualTo(tech.cwvermaak.weldforge.model.AdminRole.valueOf(role));
    }

    @Then("user {string} still has admin role {string}")
    public void userStillHasAdminRole(String email, String role) {
        userHasAdminRole(email, role);
    }
}
