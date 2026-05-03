package tech.cwvermaak.weldforge.bdd;

import io.cucumber.datatable.DataTable;
import io.cucumber.java.en.Given;
import io.cucumber.java.en.Then;
import io.cucumber.java.en.When;
import tech.cwvermaak.weldforge.model.CrmProviderType;
import tech.cwvermaak.weldforge.model.CrmProvisioningLog;
import tech.cwvermaak.weldforge.model.Tenant;
import tech.cwvermaak.weldforge.model.TenantCrmProvider;
import tech.cwvermaak.weldforge.model.User;
import tech.cwvermaak.weldforge.repository.CrmProvisioningLogRepository;
import tech.cwvermaak.weldforge.repository.TenantCrmProviderRepository;
import tech.cwvermaak.weldforge.service.audit.AuditService;
import tech.cwvermaak.weldforge.service.crm.CrmClient;
import tech.cwvermaak.weldforge.service.crm.CrmProvisioningService;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Exercises {@link CrmProvisioningService} with a fake {@link CrmClient}
 * so we can assert field mapping, upsert vs create, dedupe behaviour
 * and failure handling without a real CRM.
 */
public class EpicICrmSteps {

    private final TestWorld world;
    private final AtomicLong ids = new AtomicLong(81000);

    private TenantCrmProviderRepository providerRepository;
    private CrmProvisioningLogRepository logRepository;
    private FakeCrmClient crmClient;
    private CrmProvisioningService service;

    private final Map<Long, List<TenantCrmProvider>> providersByTenant = new LinkedHashMap<>();
    private final Map<String, TenantCrmProvider> providersByName = new LinkedHashMap<>();
    private final List<CrmProvisioningLog> logs = new ArrayList<>();

    public EpicICrmSteps(TestWorld world) {
        this.world = world;
    }

    @SuppressWarnings("unchecked")
    private void ensureWired() {
        if (service != null) return;

        providerRepository = mock(TenantCrmProviderRepository.class);
        logRepository = mock(CrmProvisioningLogRepository.class);
        crmClient = new FakeCrmClient();
        AuditService audit = mock(AuditService.class);

        when(providerRepository.findByTenantIdAndEnabledTrue(anyLong())).thenAnswer(inv ->
                providersByTenant.getOrDefault(inv.<Long>getArgument(0), List.of()).stream()
                        .filter(TenantCrmProvider::isEnabled)
                        .toList());

        when(logRepository.findByProviderIdAndUserId(anyLong(), anyLong())).thenAnswer(inv -> {
            Long pid = inv.getArgument(0);
            Long uid = inv.getArgument(1);
            return logs.stream()
                    .filter(l -> pid.equals(l.getProvider().getId()) && uid.equals(l.getUser().getId()))
                    .findFirst();
        });
        when(logRepository.findByProviderIdAndMatchKeyValue(anyLong(), anyString())).thenAnswer(inv -> {
            Long pid = inv.getArgument(0);
            String mkv = inv.getArgument(1);
            return logs.stream()
                    .filter(l -> pid.equals(l.getProvider().getId()) && mkv.equals(l.getMatchKeyValue()))
                    .findFirst();
        });
        when(logRepository.save(any(CrmProvisioningLog.class))).thenAnswer(inv -> {
            CrmProvisioningLog l = inv.getArgument(0);
            if (l.getId() == null) {
                l.setId(ids.getAndIncrement());
                logs.add(l);
            }
            return l;
        });

        service = new CrmProvisioningService(providerRepository, logRepository, crmClient, audit);
    }

    private Tenant tenant(String slug) {
        return world.tenants.computeIfAbsent(slug, s ->
                Tenant.builder().id(ids.getAndIncrement()).slug(s).name(s).enabled(true).build());
    }

    // ---- Fixtures --------------------------------------------------

    @Given("tenant {string} exists for CRM tests")
    public void tenantExists(String slug) {
        ensureWired();
        tenant(slug);
    }

    @Given("user {string} with name {string} exists in tenant {string} for CRM tests")
    public void userExists(String email, String name, String slug) {
        Tenant t = tenant(slug);
        User u = User.builder()
                .id(ids.getAndIncrement())
                .tenant(t)
                .email(email)
                .username(email)
                .name(name)
                .build();
        world.users.put(slug + "|" + email.toLowerCase(), u);
    }

    @Given("tenant {string} has a {string} CRM provider {string} at {string} with mappings:")
    public void tenantHasProvider(String slug, String type, String name, String url, DataTable mappings) {
        addProvider(slug, name, url, CrmProviderType.valueOf(type), toMappings(mappings), true);
    }

    @Given("tenant {string} has a {string} CRM provider {string} at {string}")
    public void tenantHasProviderNoMappings(String slug, String type, String name, String url) {
        // Minimal mapping so validation passes; the scenario only cares
        // that the provider exists, not what it sends.
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("source", "email");
        m.put("target", "email");
        addProvider(slug, name, url, CrmProviderType.valueOf(type), List.of(m), true);
    }

    @Given("tenant {string} has a disabled {string} CRM provider {string} at {string}")
    public void tenantHasDisabledProvider(String slug, String type, String name, String url) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("source", "email");
        m.put("target", "email");
        addProvider(slug, name, url, CrmProviderType.valueOf(type), List.of(m), false);
    }

    @Given("the CRM client will fail for provider {string} with {string}")
    public void clientWillFail(String providerName, String error) {
        crmClient.failuresByProvider.put(providerName, error);
    }

    private void addProvider(String slug, String name, String url, CrmProviderType type,
                              List<Map<String, Object>> mappings, boolean enabled) {
        Tenant t = tenant(slug);
        TenantCrmProvider p = TenantCrmProvider.builder()
                .id(ids.getAndIncrement())
                .tenant(t)
                .name(name)
                .providerType(type)
                .baseUrl(url)
                .apiToken("test-token")
                .fieldMappings(mappings)
                .matchKeys(List.of("email"))
                .enabled(enabled)
                .dedupeEnabled(true)
                .build();
        providersByTenant.computeIfAbsent(t.getId(), k -> new ArrayList<>()).add(p);
        providersByName.put(name, p);
    }

    private static List<Map<String, Object>> toMappings(DataTable table) {
        List<Map<String, Object>> out = new ArrayList<>();
        for (List<String> row : table.asLists()) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("source", row.get(0));
            m.put("target", row.get(1));
            out.add(m);
        }
        return out;
    }

    // ---- Actions ---------------------------------------------------

    @When("crm provisioning fires for {string} on event {string}")
    public void fireProvisioning(String email, String eventType) {
        User user = world.users.get("acme|" + email.toLowerCase());
        service.provisionOnEvent(eventType, user);
    }

    // ---- Assertions ------------------------------------------------

    @Then("the CRM client was called once for provider {string}")
    public void calledOnce(String providerName) {
        long count = crmClient.calls.stream()
                .filter(c -> c.providerName.equals(providerName))
                .count();
        assertThat(count).isEqualTo(1);
    }

    @Then("the CRM client was called twice for provider {string}")
    public void calledTwice(String providerName) {
        long count = crmClient.calls.stream()
                .filter(c -> c.providerName.equals(providerName))
                .count();
        assertThat(count).isEqualTo(2);
    }

    @Then("no CRM client calls were made")
    public void noCalls() {
        assertThat(crmClient.calls).isEmpty();
    }

    @Then("the outgoing payload has field {string} equal to {string}")
    public void payloadField(String key, String value) {
        FakeCrmClient.Call last = crmClient.calls.get(crmClient.calls.size() - 1);
        assertThat(last.fields).containsEntry(key, value);
    }

    @Then("the provisioning log row has status {string}")
    public void logStatus(String expected) {
        assertThat(logs).isNotEmpty();
        assertThat(logs.get(logs.size() - 1).getStatus().name()).isEqualTo(expected);
    }

    @Then("the provisioning log row has a non-null external id")
    public void logHasExternalId() {
        assertThat(logs.get(logs.size() - 1).getExternalId()).isNotNull();
    }

    @Then("the second call was an update against the existing external id")
    public void secondCallUpsert() {
        assertThat(crmClient.calls).hasSize(2);
        FakeCrmClient.Call second = crmClient.calls.get(1);
        assertThat(second.existingExternalId).isNotNull();
    }

    @Then("the provisioning log row's last error contains {string}")
    public void logErrorContains(String fragment) {
        assertThat(logs.get(logs.size() - 1).getLastError()).contains(fragment);
    }

    // ---- Fake CRM client -----------------------------------------

    static class FakeCrmClient implements CrmClient {
        static class Call {
            final String providerName;
            final String existingExternalId;
            final Map<String, Object> fields;
            Call(String providerName, String existingExternalId, Map<String, Object> fields) {
                this.providerName = providerName;
                this.existingExternalId = existingExternalId;
                this.fields = fields;
            }
        }
        final List<Call> calls = new ArrayList<>();
        final Map<String, String> failuresByProvider = new HashMap<>();
        private long nextId = 90000;

        @Override
        public Result upsert(TenantCrmProvider provider, String existingExternalId, Map<String, Object> fields) {
            calls.add(new Call(provider.getName(), existingExternalId, fields));
            String error = failuresByProvider.get(provider.getName());
            if (error != null) return new Result(false, null, 500, error);
            String id = existingExternalId != null
                    ? existingExternalId
                    : "ext-" + (nextId++);
            return new Result(true, id, 200, null);
        }
    }
}
