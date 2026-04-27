package tech.cwvermaak.intellisso.bdd;

import io.cucumber.java.en.Given;
import io.cucumber.java.en.Then;
import io.cucumber.java.en.When;
import jakarta.persistence.EntityNotFoundException;
import tech.cwvermaak.intellisso.config.tenant.TenantAccessor;
import tech.cwvermaak.intellisso.model.Tenant;
import tech.cwvermaak.intellisso.model.User;
import tech.cwvermaak.intellisso.repository.AppClientRepository;
import tech.cwvermaak.intellisso.repository.EnvironmentRepository;
import tech.cwvermaak.intellisso.repository.RoleRepository;
import tech.cwvermaak.intellisso.repository.UserRepository;
import tech.cwvermaak.intellisso.service.AdminService;
import tech.cwvermaak.intellisso.service.audit.AuditService;
import tech.cwvermaak.intellisso.service.mfa.MfaService;

import java.util.List;
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
                mock(tech.cwvermaak.intellisso.service.PasswordResetService.class));
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
}
