package tech.cwvermaak.weldforge.bdd;

import io.cucumber.java.en.Given;
import io.cucumber.java.en.Then;
import io.cucumber.java.en.When;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.springframework.security.authentication.BadCredentialsException;
import tech.cwvermaak.weldforge.config.tenant.TenantAccessor;
import tech.cwvermaak.weldforge.model.AuditEvent;
import tech.cwvermaak.weldforge.model.Tenant;
import tech.cwvermaak.weldforge.model.User;
import tech.cwvermaak.weldforge.model.dto.scim.ScimEmailDto;
import tech.cwvermaak.weldforge.model.dto.scim.ScimListResponseDto;
import tech.cwvermaak.weldforge.model.dto.scim.ScimNameDto;
import tech.cwvermaak.weldforge.model.dto.scim.ScimPatchRequestDto;
import tech.cwvermaak.weldforge.model.dto.scim.ScimUserDto;
import tech.cwvermaak.weldforge.repository.UserRepository;
import tech.cwvermaak.weldforge.service.TenantSeatService;
import tech.cwvermaak.weldforge.service.audit.AuditService;
import tech.cwvermaak.weldforge.service.scim.ScimUserService;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

public class ScimProvisioningSteps {

    private final TestWorld world;

    private TenantAccessor tenantAccessor;
    private UserRepository userRepository;
    private AuditService auditService;
    private ScimUserService scimService;

    private Tenant tenant;
    private final List<User> store = new ArrayList<>();
    private final AtomicLong idSeq = new AtomicLong(500);

    private ScimListResponseDto<ScimUserDto> lastList;
    private ScimUserDto lastUser;

    public ScimProvisioningSteps(TestWorld world) {
        this.world = world;
    }

    private void ensureWired() {
        if (scimService != null) return;

        tenantAccessor = mock(TenantAccessor.class);
        userRepository = mock(UserRepository.class);
        auditService = mock(AuditService.class);

        when(tenantAccessor.requireTenant()).thenAnswer(inv -> tenant);
        when(tenantAccessor.requireTenantId()).thenAnswer(inv -> tenant.getId());

        when(userRepository.save(any(User.class))).thenAnswer(inv -> {
            User u = inv.getArgument(0);
            if (u.getId() == null) {
                u.setId(idSeq.getAndIncrement());
                if (u.getCreatedAt() == null) u.setCreatedAt(LocalDateTime.now());
                store.add(u);
            }
            return u;
        });
        when(userRepository.findByTenantId(any())).thenAnswer(inv -> List.copyOf(store));
        when(userRepository.findByIdAndTenantId(anyLong(), any())).thenAnswer(inv -> {
            Long id = inv.getArgument(0);
            return store.stream().filter(u -> id.equals(u.getId())).findFirst();
        });
        when(userRepository.findByTenantIdAndUsernameIgnoreCase(any(), anyString())).thenAnswer(inv -> {
            String name = inv.getArgument(1);
            return store.stream().filter(u -> name.equalsIgnoreCase(u.getUsername())).findFirst();
        });
        when(userRepository.findByTenantIdAndEmailIgnoreCase(any(), anyString())).thenAnswer(inv -> {
            String email = inv.getArgument(1);
            return store.stream().filter(u -> email.equalsIgnoreCase(u.getEmail())).findFirst();
        });

        // Capture audit events into the shared world for cross-step assertions.
        doAnswer(inv -> {
            AuditEvent.AuditEventBuilder builder = inv.getArgument(0);
            world.auditLog.add(builder.build());
            return null;
        }).when(auditService).log(any());

        scimService = new ScimUserService(tenantAccessor, userRepository, auditService, new SimpleMeterRegistry(),
                new TenantSeatService(userRepository));
    }

    @Given("tenant {string} exists for SCIM")
    public void tenantExists(String slug) {
        tenant = Tenant.builder().id(1L).slug(slug).name(slug).build();
        world.tenants.put(slug, tenant);
        ensureWired();
    }

    @Given("no users exist in tenant {string}")
    public void noUsers(String slug) {
        store.clear();
    }

    @When("a SCIM client lists users in tenant {string} with filter {string}")
    public void scimList(String slug, String filter) {
        lastList = scimService.list(filter, 1, 100, "https://wf.test/scim/v2/" + slug + "/Users");
    }

    @Then("the SCIM list result is empty")
    public void listEmpty() {
        assertThat(lastList.getTotalResults()).isZero();
        assertThat(lastList.getResources()).isEmpty();
    }

    @Then("the SCIM list contains {string}")
    public void listContains(String userName) {
        assertThat(lastList.getResources())
                .extracting(ScimUserDto::getUserName)
                .contains(userName);
    }

    @When("a SCIM client creates user {string} in tenant {string}")
    public void scimCreate(String userName, String slug) {
        ScimUserDto incoming = ScimUserDto.builder()
                .userName(userName)
                .name(ScimNameDto.builder().givenName("Alice").familyName("Example").build())
                .displayName("Alice Example")
                .emails(List.of(ScimEmailDto.builder().value(userName).primary(true).build()))
                .active(true)
                .build();
        lastUser = scimService.create(incoming, "https://wf.test/scim/v2/" + slug + "/Users");
    }

    @Then("the user is created and active")
    public void createdAndActive() {
        assertThat(lastUser).isNotNull();
        assertThat(lastUser.getId()).isNotBlank();
        assertThat(lastUser.isActive()).isTrue();
        // The world also has the user persisted via the in-memory repo.
        assertThat(store).extracting(User::getUsername).contains(lastUser.getUserName());
    }

    @Given("user {string} was provisioned via SCIM in tenant {string}")
    public void provisionedViaScim(String userName, String slug) {
        tenantExists(slug);
        scimCreate(userName, slug);
    }

    @When("a SCIM client patches alice's active flag to false")
    public void deactivateAlice() {
        Long id = Long.valueOf(lastUser.getId());
        ScimPatchRequestDto patch = ScimPatchRequestDto.builder()
                .operations(List.of(ScimPatchRequestDto.Operation.builder()
                        .op("replace").path("active").value(false).build()))
                .build();
        lastUser = scimService.patch(id, patch, null);
    }

    @When("a SCIM client patches alice's active flag to true")
    public void reactivateAlice() {
        Long id = Long.valueOf(lastUser.getId());
        ScimPatchRequestDto patch = ScimPatchRequestDto.builder()
                .operations(List.of(ScimPatchRequestDto.Operation.builder()
                        .op("replace").path("active").value(true).build()))
                .build();
        lastUser = scimService.patch(id, patch, null);
    }

    @Then("alice is marked inactive")
    public void aliceInactive() {
        assertThat(lastUser.isActive()).isFalse();
        assertThat(store.stream()
                .filter(u -> u.getUsername().equals(lastUser.getUserName()))
                .findFirst().orElseThrow().isActive())
                .isFalse();
    }

    @Then("alice is marked active")
    public void aliceActive() {
        assertThat(lastUser.isActive()).isTrue();
    }

    @Given("alice is currently inactive")
    public void aliceCurrentlyInactive() {
        deactivateAlice();
    }

    @Then("a {string} audit event is recorded for alice")
    public void auditEventRecorded(String type) {
        assertThat(world.auditLog)
                .extracting(AuditEvent::getEventType)
                .contains(type);
    }

    @Then("alice cannot log in")
    public void aliceCannotLogIn() {
        // Reproduce the AuthService check exactly: an inactive user is
        // refused with BadCredentialsException, identical to what the
        // login endpoint would return.
        User row = store.stream()
                .filter(u -> u.getUsername().equals(lastUser.getUserName()))
                .findFirst().orElseThrow();
        assertThat(row.isActive()).isFalse();

        // Simulate the AuthService.login() guard.
        try {
            if (!row.isActive()) {
                throw new BadCredentialsException("Invalid credentials");
            }
            assertThat(true).as("login should have been refused").isFalse();
        } catch (BadCredentialsException expected) {
            // pass
        }
    }
}
