package tech.cwvermaak.weldforge.bdd;

import io.cucumber.java.After;
import io.cucumber.java.en.Given;
import io.cucumber.java.en.Then;
import io.cucumber.java.en.When;
import org.springframework.security.access.AccessDeniedException;
import tech.cwvermaak.weldforge.config.tenant.TenantAccessor;
import tech.cwvermaak.weldforge.config.tenant.TenantContext;
import tech.cwvermaak.weldforge.model.AdminMembership;
import tech.cwvermaak.weldforge.model.AdminRole;
import tech.cwvermaak.weldforge.model.Tenant;
import tech.cwvermaak.weldforge.model.User;
import tech.cwvermaak.weldforge.model.dto.AdminMembershipDto;
import tech.cwvermaak.weldforge.repository.AdminMembershipRepository;
import tech.cwvermaak.weldforge.repository.TenantRepository;
import tech.cwvermaak.weldforge.repository.UserRepository;
import tech.cwvermaak.weldforge.service.AdminMembershipService;
import tech.cwvermaak.weldforge.service.audit.AuditService;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicLong;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.*;

/**
 * Step definitions for cross_tenant_membership.feature — exercises the real
 * {@link AdminMembershipService} + {@link TenantAccessor} over mocked repos.
 */
public class CrossTenantMembershipSteps {

    private AdminMembershipService service;
    private final List<AdminMembership> store = new ArrayList<>();
    private final AtomicLong idSeq = new AtomicLong(900);
    private final Tenant beta = Tenant.builder().id(2L).slug("beta").name("Beta").build();
    private User target;

    private Throwable error;
    private AdminMembershipDto granted;

    private void ensureWired() {
        if (service != null) return;

        AdminMembershipRepository membershipRepository = mock(AdminMembershipRepository.class);
        UserRepository userRepository = mock(UserRepository.class);
        TenantRepository tenantRepository = mock(TenantRepository.class);
        AuditService auditService = mock(AuditService.class);

        when(membershipRepository.findByUser_Id(anyLong())).thenAnswer(inv -> {
            Long uid = inv.getArgument(0);
            return store.stream()
                    .filter(m -> m.getUser() != null && uid.equals(m.getUser().getId()))
                    .toList();
        });
        when(membershipRepository.save(any(AdminMembership.class))).thenAnswer(inv -> {
            AdminMembership m = inv.getArgument(0);
            if (m.getId() == null) {
                m.setId(idSeq.getAndIncrement());
                store.add(m);
            }
            return m;
        });
        when(membershipRepository.findByIdAndUser_Id(anyLong(), anyLong())).thenAnswer(inv -> {
            Long id = inv.getArgument(0);
            Long uid = inv.getArgument(1);
            return store.stream()
                    .filter(m -> id.equals(m.getId())
                            && m.getUser() != null && uid.equals(m.getUser().getId()))
                    .findFirst();
        });
        doAnswer(inv -> { store.remove(inv.<AdminMembership>getArgument(0)); return null; })
                .when(membershipRepository).delete(any(AdminMembership.class));

        when(userRepository.findById(anyLong())).thenAnswer(inv ->
                target != null && target.getId().equals(inv.getArgument(0))
                        ? Optional.of(target) : Optional.empty());
        when(tenantRepository.findById(anyLong())).thenAnswer(inv ->
                beta.getId().equals(inv.getArgument(0)) ? Optional.of(beta) : Optional.empty());

        TenantAccessor accessor = new TenantAccessor(tenantRepository, membershipRepository);
        service = new AdminMembershipService(accessor, membershipRepository,
                userRepository, tenantRepository, auditService);
    }

    @After
    public void cleanup() {
        TenantContext.clear();
    }

    @Given("a target user {string} for membership management")
    public void targetUser(String email) {
        ensureWired();
        target = User.builder()
                .id(500L)
                .tenant(Tenant.builder().id(1L).slug("acme").name("Acme").build())
                .email(email)
                .username(email)
                .build();
    }

    @Given("the caller is a global super admin")
    public void callerGlobalSuperAdmin() {
        ensureWired();
        TenantContext.set("acme", 1L, AdminRole.SUPER_ADMIN);
        TenantContext.setActorServiceAccount(1L);
    }

    @Given("the caller is only a tenant admin")
    public void callerTenantAdmin() {
        ensureWired();
        TenantContext.set("acme", 1L, AdminRole.TENANT_ADMIN);
        TenantContext.setActorServiceAccount(1L);
    }

    @Given("{string} already has a TENANT_ADMIN membership on tenant {string}")
    public void existingMembership(String email, String tenantSlug) {
        store.add(AdminMembership.builder()
                .id(idSeq.getAndIncrement())
                .user(target)
                .tenant(beta)
                .adminRole(AdminRole.TENANT_ADMIN)
                .build());
    }

    @When("the caller grants {string} role {word} on tenant {string}")
    public void grantPerTenant(String email, String role, String tenantSlug) {
        invokeGrant(role, beta.getId());
    }

    @When("the caller grants {string} role {word} globally")
    public void grantGlobal(String email, String role) {
        invokeGrant(role, null);
    }

    private void invokeGrant(String role, Long tenantId) {
        error = null;
        granted = null;
        try {
            granted = service.grant(target.getId(), AdminMembershipDto.builder()
                    .adminRole(AdminRole.valueOf(role))
                    .tenantId(tenantId)
                    .build());
        } catch (Throwable t) {
            error = t;
        }
    }

    @When("the caller revokes that membership")
    public void revokeMembership() {
        error = null;
        Long id = store.get(store.size() - 1).getId();
        try {
            service.revoke(target.getId(), id);
        } catch (Throwable t) {
            error = t;
        }
    }

    @Then("the membership grant succeeds")
    public void grantSucceeds() {
        assertThat(error).isNull();
        assertThat(granted).isNotNull();
    }

    @Then("the membership grant is rejected as a bad request")
    public void grantRejected() {
        assertThat(error).isInstanceOf(IllegalArgumentException.class);
    }

    @Then("the membership grant is denied")
    public void grantDenied() {
        assertThat(error).isInstanceOf(AccessDeniedException.class);
    }

    @Then("{string} has {int} admin membership(s)")
    public void membershipCount(String email, int expected) {
        long count = store.stream()
                .filter(m -> m.getUser() != null && target.getId().equals(m.getUser().getId()))
                .count();
        assertThat(count).isEqualTo((long) expected);
    }
}
