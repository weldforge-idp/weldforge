package tech.cwvermaak.weldforge.bdd;

import io.cucumber.java.After;
import io.cucumber.java.en.Given;
import io.cucumber.java.en.Then;
import io.cucumber.java.en.When;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import tech.cwvermaak.weldforge.config.tenant.TenantAccessor;
import tech.cwvermaak.weldforge.config.tenant.TenantContext;
import tech.cwvermaak.weldforge.model.AdminRole;
import tech.cwvermaak.weldforge.model.AuditEvent;
import tech.cwvermaak.weldforge.model.OidcClient;
import tech.cwvermaak.weldforge.model.Tenant;
import tech.cwvermaak.weldforge.model.User;
import tech.cwvermaak.weldforge.model.dto.OidcClientDto;
import tech.cwvermaak.weldforge.model.dto.TenantDto;
import tech.cwvermaak.weldforge.repository.AppClientRepository;
import tech.cwvermaak.weldforge.repository.EnvironmentRepository;
import tech.cwvermaak.weldforge.repository.OidcClientRepository;
import tech.cwvermaak.weldforge.repository.RoleRepository;
import tech.cwvermaak.weldforge.repository.TenantRepository;
import tech.cwvermaak.weldforge.repository.TenantSocialProviderRepository;
import tech.cwvermaak.weldforge.repository.UserRepository;
import tech.cwvermaak.weldforge.service.AdminService;
import tech.cwvermaak.weldforge.service.TenantService;
import tech.cwvermaak.weldforge.service.audit.AuditService;
import tech.cwvermaak.weldforge.service.mfa.MfaService;
import tech.cwvermaak.weldforge.service.oidc.OidcClientService;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicLong;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

public class EpicDRbacSteps {

    private final TestWorld world;
    private final AtomicLong ids = new AtomicLong(22000);

    // Mocks
    private TenantRepository tenantRepository;
    private UserRepository userRepository;
    private OidcClientRepository oidcClientRepository;
    private TenantSocialProviderRepository socialRepo;
    private RoleRepository roleRepository;
    private EnvironmentRepository envRepo;
    private AppClientRepository appClientRepo;
    private MfaService mfaService;
    private AuditService auditService;

    // Services under test — real TenantAccessor so the TenantContext-driven
    // guard checks behave exactly as they do at runtime.
    private TenantAccessor tenantAccessor;
    private TenantService tenantService;
    private AdminService adminService;
    private OidcClientService oidcClientService;

    // Store
    private final Map<String, Tenant> tenantsBySlug = new HashMap<>();
    private final Map<String, User> users = new HashMap<>();
    private final List<OidcClient> oidcClientStore = new ArrayList<>();

    // Scenario state
    private Throwable lastError;
    private Object lastResult;

    public EpicDRbacSteps(TestWorld world) {
        this.world = world;
    }

    @After
    public void clearContext() {
        TenantContext.clear();
        SecurityContextHolder.clearContext();
    }

    // ---- Wiring ----------------------------------------------------

    private void ensureWired() {
        if (tenantService != null) return;

        tenantRepository = mock(TenantRepository.class);
        userRepository = mock(UserRepository.class);
        oidcClientRepository = mock(OidcClientRepository.class);
        socialRepo = mock(TenantSocialProviderRepository.class);
        roleRepository = mock(RoleRepository.class);
        envRepo = mock(EnvironmentRepository.class);
        appClientRepo = mock(AppClientRepository.class);
        mfaService = mock(MfaService.class);
        auditService = mock(AuditService.class);

        when(tenantRepository.findById(anyLong())).thenAnswer(inv -> {
            Long id = inv.getArgument(0);
            return tenantsBySlug.values().stream().filter(t -> id.equals(t.getId())).findFirst();
        });
        when(tenantRepository.findBySlug(anyString())).thenAnswer(inv -> {
            String slug = inv.getArgument(0);
            return Optional.ofNullable(tenantsBySlug.get(slug));
        });
        when(tenantRepository.existsBySlug(anyString())).thenAnswer(inv ->
                tenantsBySlug.containsKey(inv.getArgument(0)));
        when(tenantRepository.findAll()).thenAnswer(inv -> new ArrayList<>(tenantsBySlug.values()));
        when(tenantRepository.save(any(Tenant.class))).thenAnswer(inv -> {
            Tenant t = inv.getArgument(0);
            if (t.getId() == null) t.setId(ids.getAndIncrement());
            tenantsBySlug.put(t.getSlug(), t);
            return t;
        });

        when(userRepository.findById(anyLong())).thenAnswer(inv -> {
            Long id = inv.getArgument(0);
            return users.values().stream().filter(u -> id.equals(u.getId())).findFirst();
        });
        // Tenant-scoped lookup used by setAdminRole/setUserRole/etc. — returns a
        // user only when both id and tenant match (mirrors the real query).
        when(userRepository.findByIdAndTenantId(anyLong(), anyLong())).thenAnswer(inv -> {
            Long id = inv.getArgument(0);
            Long tid = inv.getArgument(1);
            return users.values().stream()
                    .filter(u -> id.equals(u.getId())
                            && u.getTenant() != null && tid.equals(u.getTenant().getId()))
                    .findFirst();
        });
        when(userRepository.findByTenant_SlugAndEmailIgnoreCase(anyString(), anyString())).thenAnswer(inv -> {
            String slug = inv.getArgument(0);
            String email = inv.getArgument(1);
            return Optional.ofNullable(users.get(slug + "|" + email.toLowerCase()));
        });
        when(userRepository.save(any(User.class))).thenAnswer(inv -> inv.getArgument(0));

        when(oidcClientRepository.findByTenantId(anyLong())).thenAnswer(inv -> {
            Long tid = inv.getArgument(0);
            return oidcClientStore.stream().filter(c -> c.getTenant().getId().equals(tid)).toList();
        });
        when(oidcClientRepository.findByTenantIdAndClientId(anyLong(), anyString())).thenAnswer(inv -> {
            Long tid = inv.getArgument(0);
            String cid = inv.getArgument(1);
            return oidcClientStore.stream()
                    .filter(c -> c.getTenant().getId().equals(tid) && cid.equals(c.getClientId()))
                    .findFirst();
        });
        when(oidcClientRepository.save(any(OidcClient.class))).thenAnswer(inv -> {
            OidcClient c = inv.getArgument(0);
            if (c.getId() == null) c.setId(ids.getAndIncrement());
            oidcClientStore.add(c);
            return c;
        });

        doAnswer(inv -> {
            world.auditLog.add(AuditEvent.builder()
                    .eventType(inv.getArgument(0))
                    .outcome(AuditEvent.Outcome.SUCCESS)
                    .build());
            return null;
        }).when(auditService).recordAdmin(anyString(), any(), anyString(), anyString(), any());

        // Real TenantAccessor so the RBAC guards actually run.
        tenantAccessor = new TenantAccessor(tenantRepository,
                mock(tech.cwvermaak.weldforge.repository.AdminMembershipRepository.class));

        tech.cwvermaak.weldforge.config.tenant.PublicHostProperties publicHost =
                new tech.cwvermaak.weldforge.config.tenant.PublicHostProperties();
        publicHost.setBaseDomain("sso.weldforge.org");
        publicHost.setScheme("https");
        tenantService = new TenantService(tenantAccessor, tenantRepository, socialRepo, userRepository,
                mock(tech.cwvermaak.weldforge.repository.RefreshTokenRepository.class),
                mock(tech.cwvermaak.weldforge.repository.TenantSlugHoldbackRepository.class),
                auditService, publicHost,
                new tech.cwvermaak.weldforge.service.TenantSlugValidator(
                        publicHost, mock(tech.cwvermaak.weldforge.repository.TenantSlugHoldbackRepository.class)));
        adminService = new AdminService(tenantAccessor, roleRepository, userRepository,
                envRepo, appClientRepo, mfaService, auditService,
                mock(tech.cwvermaak.weldforge.service.PasswordResetService.class),
                new tech.cwvermaak.weldforge.service.TenantSeatService(userRepository));
        oidcClientService = new OidcClientService(tenantAccessor, oidcClientRepository);
    }

    private Tenant tenant(String slug) {
        return tenantsBySlug.computeIfAbsent(slug, s ->
                Tenant.builder().id(ids.getAndIncrement()).slug(s).name(s).enabled(true).build());
    }

    /**
     * Put alice into the request-scoped TenantContext with the given role,
     * so every call to tenantAccessor.requireXxx() reads that role.
     */
    private void actAs(User user, AdminRole role) {
        user.setAdminRole(role);
        user.setSuperAdmin(role == AdminRole.SUPER_ADMIN);
        TenantContext.set(user.getTenant().getSlug(), user.getTenant().getId(), role);
        var auth = new UsernamePasswordAuthenticationToken(user.getEmail(), null, java.util.List.of());
        SecurityContextHolder.getContext().setAuthentication(auth);
    }

    // ---- Background ------------------------------------------------

    @Given("tenant {string} exists for RBAC tests")
    public void tenantExists(String slug) {
        ensureWired();
        Tenant t = tenant(slug);
        when(tenantRepository.save(any(Tenant.class))).thenAnswer(inv -> {
            Tenant saved = inv.getArgument(0);
            if (saved.getId() == null) saved.setId(ids.getAndIncrement());
            tenantsBySlug.put(saved.getSlug(), saved);
            return saved;
        });
    }

    @Given("user {string} exists in tenant {string} for RBAC tests")
    public void userExists(String email, String slug) {
        Tenant t = tenant(slug);
        User u = User.builder()
                .id(ids.getAndIncrement())
                .tenant(t)
                .email(email)
                .username(email)
                .password("hashed")
                .adminRole(AdminRole.NONE)
                .tokenVersion(0)
                .build();
        users.put(slug + "|" + email.toLowerCase(), u);
    }

    @Given("user {string} exists in tenant {string} with token version {int} for RBAC tests")
    public void userExistsWithTokenVersion(String email, String slug, int version) {
        Tenant t = tenant(slug);
        User u = User.builder()
                .id(ids.getAndIncrement())
                .tenant(t)
                .email(email)
                .username(email)
                .password("hashed")
                .adminRole(AdminRole.NONE)
                .tokenVersion(version)
                .build();
        users.put(slug + "|" + email.toLowerCase(), u);
    }

    // ---- Role setup ------------------------------------------------

    @Given("alice has admin role {word}")
    public void aliceHasRole(String roleName) {
        User alice = users.get("acme|alice@acme.test");
        actAs(alice, AdminRole.valueOf(roleName));
    }

    // ---- OIDC operations -------------------------------------------

    @When("alice tries to list OIDC clients")
    public void aliceTriesListOidc() {
        lastError = null;
        try {
            lastResult = oidcClientService.list();
        } catch (Exception e) {
            lastError = e;
        }
    }

    @When("alice lists OIDC clients")
    public void aliceListsOidc() {
        aliceTriesListOidc();
    }

    @When("alice tries to create an OIDC client")
    public void aliceTriesCreateOidc() {
        lastError = null;
        OidcClientDto dto = OidcClientDto.builder()
                .clientId("forbidden")
                .redirectUris(List.of("https://app.test/cb"))
                .scopes(List.of("openid"))
                .grantTypes(List.of("authorization_code"))
                .build();
        try {
            lastResult = oidcClientService.create(dto);
        } catch (Exception e) {
            lastError = e;
        }
    }

    @When("alice creates an OIDC client {string}")
    public void aliceCreatesOidc(String clientId) {
        lastError = null;
        OidcClientDto dto = OidcClientDto.builder()
                .clientId(clientId)
                .redirectUris(List.of("https://app.test/cb"))
                .scopes(List.of("openid"))
                .grantTypes(List.of("authorization_code"))
                .build();
        try {
            lastResult = oidcClientService.create(dto);
        } catch (Exception e) {
            lastError = e;
        }
    }

    @Then("the client is created")
    public void clientCreated() {
        assertThat(lastError).isNull();
        assertThat(lastResult).isInstanceOf(OidcClientDto.class);
        assertThat(oidcClientStore).isNotEmpty();
    }

    // ---- Tenant create ---------------------------------------------

    @When("alice tries to create a new tenant {string}")
    public void aliceTriesCreateTenant(String slug) {
        lastError = null;
        try {
            lastResult = tenantService.createTenant(TenantDto.builder().slug(slug).name(slug).build());
        } catch (Exception e) {
            lastError = e;
        }
    }

    @When("alice creates a new tenant {string}")
    public void aliceCreatesTenant(String slug) {
        aliceTriesCreateTenant(slug);
    }

    @Then("the tenant is created")
    public void tenantIsCreated() {
        assertThat(lastError).isNull();
        assertThat(lastResult).isInstanceOf(TenantDto.class);
    }

    // ---- Admin role assignment -------------------------------------

    @When("alice assigns admin role {word} to bob")
    public void aliceAssignsRoleToBob(String roleName) {
        lastError = null;
        User bob = users.get("acme|bob@acme.test");
        try {
            lastResult = adminService.setAdminRole(bob.getId(), AdminRole.valueOf(roleName));
        } catch (Exception e) {
            lastError = e;
        }
    }

    @When("alice tries to assign admin role {word} to bob")
    public void aliceTriesAssignsRoleToBob(String roleName) {
        aliceAssignsRoleToBob(roleName);
    }

    @Then("bob's admin role is {word}")
    public void bobRoleIs(String expected) {
        User bob = users.get("acme|bob@acme.test");
        assertThat(bob.getAdminRole().name()).isEqualTo(expected);
    }

    @Then("bob's token version is {int}")
    public void bobTokenVersionIs(int expected) {
        User bob = users.get("acme|bob@acme.test");
        assertThat(bob.getTokenVersion()).isEqualTo(expected);
    }

    @Then("an {string} audit event is recorded for RBAC")
    public void auditRecorded(String type) {
        assertThat(world.auditLog).extracting(AuditEvent::getEventType).contains(type);
    }

    // ---- Common assertions -----------------------------------------

    @Then("the call is rejected as access denied")
    public void callRejected() {
        assertThat(lastError).isInstanceOf(AccessDeniedException.class);
    }

    @Then("the call succeeds")
    public void callSucceeded() {
        assertThat(lastError).isNull();
    }
}
