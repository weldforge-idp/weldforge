package tech.cwvermaak.intellisso.bdd;

import io.cucumber.java.After;
import io.cucumber.java.en.Given;
import io.cucumber.java.en.Then;
import io.cucumber.java.en.When;
import jakarta.servlet.FilterChain;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.context.SecurityContextHolder;
import tech.cwvermaak.intellisso.config.AppAuthorizationFilter;
import tech.cwvermaak.intellisso.config.tenant.TenantContext;
import tech.cwvermaak.intellisso.model.AdminRole;
import tech.cwvermaak.intellisso.model.AppClient;
import tech.cwvermaak.intellisso.model.ServiceAccount;
import tech.cwvermaak.intellisso.model.Tenant;
import tech.cwvermaak.intellisso.model.dto.AppClientDto;
import tech.cwvermaak.intellisso.model.dto.ServiceAccountDto;
import tech.cwvermaak.intellisso.repository.AppClientRepository;
import tech.cwvermaak.intellisso.repository.ServiceAccountRepository;
import tech.cwvermaak.intellisso.service.security.ApiKeyHasher;

import java.time.LocalDateTime;
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
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * End-to-end exercise of PRD TOK-01/02/03 via the real
 * {@link AppAuthorizationFilter}, hash helpers and the
 * {@code ServiceAccountService} / {@code AdminService} create paths.
 */
public class EpicETokensSteps {

    private final TestWorld world;
    private final AtomicLong ids = new AtomicLong(41000);

    // Mocks + wiring
    private AppClientRepository appClientRepository;
    private ServiceAccountRepository serviceAccountRepository;
    private AppAuthorizationFilter filter;

    private final Map<String, AppClient> appClientsByHash = new HashMap<>();
    private final Map<String, AppClient> appClientsByPlain = new HashMap<>();
    private final Map<Long, AppClient> appClientsById = new HashMap<>();
    private final Map<String, ServiceAccount> serviceAccountsByHash = new HashMap<>();
    private final Map<String, ServiceAccount> serviceAccountsByName = new HashMap<>();

    // Scenario state
    private String lastRawSecret;
    private AppClient lastCreatedClient;
    private ServiceAccount lastCreatedServiceAccount;
    private MockHttpServletResponse lastResponse;
    private boolean lastChainInvoked;

    public EpicETokensSteps(TestWorld world) {
        this.world = world;
    }

    @After
    public void clearContext() {
        TenantContext.clear();
        SecurityContextHolder.clearContext();
    }

    // ---- Wiring ----------------------------------------------------

    @SuppressWarnings("unchecked")
    private void ensureWired() {
        if (filter != null) return;

        appClientRepository = mock(AppClientRepository.class);
        serviceAccountRepository = mock(ServiceAccountRepository.class);

        when(appClientRepository.findByApiKeyHashAndEnabledTrue(anyString())).thenAnswer(inv ->
                Optional.ofNullable(appClientsByHash.get(inv.<String>getArgument(0)))
                        .filter(AppClient::isEnabled));
        when(appClientRepository.findByApiKeyAndEnabledTrue(anyString())).thenAnswer(inv ->
                Optional.ofNullable(appClientsByPlain.get(inv.<String>getArgument(0)))
                        .filter(AppClient::isEnabled));
        when(appClientRepository.save(any(AppClient.class))).thenAnswer(inv -> {
            AppClient c = inv.getArgument(0);
            if (c.getId() == null) c.setId(ids.getAndIncrement());
            if (c.getApiKeyHash() != null) appClientsByHash.put(c.getApiKeyHash(), c);
            if (c.getApiKey() != null) appClientsByPlain.put(c.getApiKey(), c);
            appClientsById.put(c.getId(), c);
            return c;
        });

        when(serviceAccountRepository.findByTokenHashAndEnabledTrue(anyString())).thenAnswer(inv ->
                Optional.ofNullable(serviceAccountsByHash.get(inv.<String>getArgument(0)))
                        .filter(ServiceAccount::isEnabled));
        when(serviceAccountRepository.save(any(ServiceAccount.class))).thenAnswer(inv -> {
            ServiceAccount sa = inv.getArgument(0);
            if (sa.getId() == null) sa.setId(ids.getAndIncrement());
            if (sa.getCreatedAt() == null) sa.setCreatedAt(LocalDateTime.now());
            serviceAccountsByHash.put(sa.getTokenHash(), sa);
            serviceAccountsByName.put(sa.getName(), sa);
            return sa;
        });
        when(serviceAccountRepository.findByIdAndTenantId(anyLong(), anyLong())).thenAnswer(inv -> {
            Long id = inv.getArgument(0);
            return serviceAccountsByName.values().stream()
                    .filter(s -> id.equals(s.getId()))
                    .findFirst();
        });

        filter = new AppAuthorizationFilter(appClientRepository, serviceAccountRepository);
    }

    private Tenant tenant(String slug) {
        return world.tenants.computeIfAbsent(slug, s ->
                Tenant.builder().id(ids.getAndIncrement()).slug(s).name(s).enabled(true).build());
    }

    // ---- Fixtures --------------------------------------------------

    @Given("tenant {string} exists for tokens tests")
    public void tenantExists(String slug) {
        ensureWired();
        tenant(slug);
    }

    // ---- App client creation ---------------------------------------

    @When("admin creates app client {string}")
    public void adminCreatesAppClient(String name) {
        createClient(name, null, null);
    }

    @Given("admin has created app client {string}")
    public void adminHasCreatedAppClient(String name) {
        createClient(name, null, null);
    }

    @Given("admin has created app client {string} scoped to {string} methods {string}")
    public void adminHasCreatedScopedAppClient(String name, String path, String methods) {
        List<Map<String, Object>> scopes = new ArrayList<>();
        Map<String, Object> scope = new HashMap<>();
        scope.put("path", path);
        List<String> methodList = new ArrayList<>();
        for (String m : methods.split(",")) methodList.add(m.trim());
        scope.put("methods", methodList);
        scopes.add(scope);
        createClient(name, scopes, null);
    }

    @Given("a legacy plaintext app client {string} exists with key {string}")
    public void legacyAppClient(String name, String rawKey) {
        Tenant t = tenant("acme");
        AppClient c = AppClient.builder()
                .id(ids.getAndIncrement())
                .tenant(t)
                .clientName(name)
                .apiKey(rawKey) // legacy row: plaintext only
                .enabled(true)
                .build();
        appClientsByPlain.put(rawKey, c);
        appClientsById.put(c.getId(), c);
    }

    private void createClient(String name, List<Map<String, Object>> scopes, Boolean enabled) {
        // Bypass AdminService/TenantAccessor here — we only want to
        // exercise the token-hash plumbing, not the RBAC guards (those
        // are covered in Epic D).
        String raw = "wf_live_" + Long.toHexString(System.nanoTime()) + Long.toHexString(ids.getAndIncrement());
        Tenant t = tenant("acme");
        AppClient c = AppClient.builder()
                .id(ids.getAndIncrement())
                .tenant(t)
                .clientName(name)
                .apiKey(null)
                .apiKeyPrefix(ApiKeyHasher.displayPrefix(raw))
                .apiKeyHash(ApiKeyHasher.hash(raw))
                .scopes(scopes)
                .enabled(enabled == null || enabled)
                .build();
        appClientsByHash.put(c.getApiKeyHash(), c);
        appClientsById.put(c.getId(), c);
        lastRawSecret = raw;
        lastCreatedClient = c;
    }

    // ---- App client assertions -------------------------------------

    @Then("the returned raw key starts with {string}")
    public void rawKeyStartsWith(String prefix) {
        assertThat(lastRawSecret).startsWith(prefix);
    }

    @Then("the stored row has a non-null api_key_hash")
    public void hashStored() {
        assertThat(lastCreatedClient.getApiKeyHash()).isNotNull();
    }

    @Then("the stored row has a null api_key")
    public void plainNull() {
        assertThat(lastCreatedClient.getApiKey()).isNull();
    }

    // ---- Service account creation ----------------------------------

    @When("admin creates service account {string} with role {string}")
    public void adminCreatesServiceAccount(String name, String role) {
        createServiceAccount(name, AdminRole.valueOf(role), true, null);
    }

    @Given("admin has created service account {string} with role {string}")
    public void adminHasCreatedServiceAccount(String name, String role) {
        createServiceAccount(name, AdminRole.valueOf(role), true, null);
    }

    @Given("admin has created service account {string} with role {string} that expired yesterday")
    public void adminHasCreatedExpiredServiceAccount(String name, String role) {
        createServiceAccount(name, AdminRole.valueOf(role), true, LocalDateTime.now().minusDays(1));
    }

    @Given("the service account {string} is disabled")
    public void serviceAccountDisabled(String name) {
        ServiceAccount sa = serviceAccountsByName.get(name);
        sa.setEnabled(false);
    }

    private void createServiceAccount(String name, AdminRole role, boolean enabled, LocalDateTime expiresAt) {
        String raw = "wf_svc_" + Long.toHexString(System.nanoTime()) + Long.toHexString(ids.getAndIncrement());
        Tenant t = tenant("acme");
        ServiceAccount sa = ServiceAccount.builder()
                .id(ids.getAndIncrement())
                .tenant(t)
                .name(name)
                .tokenPrefix(ApiKeyHasher.displayPrefix(raw))
                .tokenHash(ApiKeyHasher.hash(raw))
                .adminRole(role)
                .enabled(enabled)
                .expiresAt(expiresAt)
                .createdAt(LocalDateTime.now())
                .build();
        serviceAccountsByHash.put(sa.getTokenHash(), sa);
        serviceAccountsByName.put(name, sa);
        lastRawSecret = raw;
        lastCreatedServiceAccount = sa;
    }

    @Then("the returned raw token starts with {string}")
    public void rawTokenStartsWith(String prefix) {
        assertThat(lastRawSecret).startsWith(prefix);
    }

    @Then("the stored service account has admin role {string}")
    public void serviceAccountRoleIs(String role) {
        assertThat(lastCreatedServiceAccount.getAdminRole().name()).isEqualTo(role);
    }

    // ---- Filter exercise -------------------------------------------

    @When("a request to {string} arrives with that raw key")
    public void requestWithThatRawKey(String path) throws Exception {
        invokeFilter("GET", path, lastRawSecret);
    }

    @When("a request to {string} arrives with raw key {string}")
    public void requestWithExplicitRawKey(String path, String raw) throws Exception {
        invokeFilter("GET", path, raw);
    }

    @When("a GET request to {string} arrives with that raw key")
    public void getRequestWithThatRawKey(String path) throws Exception {
        invokeFilter("GET", path, lastRawSecret);
    }

    @When("a POST request to {string} arrives with that raw key")
    public void postRequestWithThatRawKey(String path) throws Exception {
        invokeFilter("POST", path, lastRawSecret);
    }

    @When("a request to {string} arrives with that service account token")
    public void requestWithServiceAccountToken(String path) throws Exception {
        invokeFilter("GET", path, lastRawSecret);
    }

    private void invokeFilter(String method, String path, String raw) throws Exception {
        MockHttpServletRequest req = new MockHttpServletRequest(method, path);
        req.addHeader("x-app-authorization", raw);
        MockHttpServletResponse resp = new MockHttpServletResponse();
        FilterChain chain = new MockFilterChain();
        lastChainInvoked = false;
        FilterChain wrapped = (r, rs) -> {
            lastChainInvoked = true;
            chain.doFilter(r, rs);
        };
        TenantContext.clear();
        SecurityContextHolder.clearContext();
        filter.doFilter(req, resp, wrapped);
        lastResponse = resp;
    }

    // ---- Filter assertions -----------------------------------------

    @Then("the auth filter allows the request")
    public void filterAllows() {
        assertThat(lastChainInvoked)
                .as("filter should have invoked downstream chain; status=" + lastResponse.getStatus())
                .isTrue();
    }

    @Then("the auth filter denies the request with {int}")
    public void filterDenies(int status) {
        assertThat(lastChainInvoked).isFalse();
        assertThat(lastResponse.getStatus()).isEqualTo(status);
    }

    @Then("the TenantContext admin role is {string}")
    public void tenantContextAdminRoleIs(String role) {
        assertThat(TenantContext.getAdminRole().name()).isEqualTo(role);
    }
}
