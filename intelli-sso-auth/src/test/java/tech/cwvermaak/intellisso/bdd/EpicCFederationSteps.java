package tech.cwvermaak.intellisso.bdd;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.cucumber.datatable.DataTable;
import io.cucumber.java.en.Given;
import io.cucumber.java.en.Then;
import io.cucumber.java.en.When;
import tech.cwvermaak.intellisso.model.Tenant;
import tech.cwvermaak.intellisso.model.User;
import tech.cwvermaak.intellisso.repository.UserRepository;
import tech.cwvermaak.intellisso.service.federation.FederationRulesEngine;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicLong;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class EpicCFederationSteps {

    private final TestWorld world;
    private final AtomicLong ids = new AtomicLong(31000);
    private final ObjectMapper json = new ObjectMapper();

    private UserRepository userRepository;
    private FederationRulesEngine engine;

    // Scenario state
    private Optional<User> matchResult;
    private Map<String, Object> transformedResult;

    public EpicCFederationSteps(TestWorld world) {
        this.world = world;
    }

    private void ensureWired() {
        if (engine != null) return;
        userRepository = mock(UserRepository.class);

        when(userRepository.findByTenantIdAndEmailIgnoreCase(anyLong(), anyString())).thenAnswer(inv -> {
            Long tid = inv.getArgument(0);
            String email = ((String) inv.getArgument(1)).toLowerCase();
            return world.users.values().stream()
                    .filter(u -> u.getTenant() != null && tid.equals(u.getTenant().getId()))
                    .filter(u -> u.getEmail() != null && u.getEmail().equalsIgnoreCase(email))
                    .findFirst();
        });
        when(userRepository.findByTenantIdAndCellPhoneNumber(anyLong(), anyString())).thenAnswer(inv -> {
            Long tid = inv.getArgument(0);
            String phone = inv.getArgument(1);
            return world.users.values().stream()
                    .filter(u -> u.getTenant() != null && tid.equals(u.getTenant().getId()))
                    .filter(u -> phone.equals(u.getCellPhoneNumber()))
                    .findFirst();
        });
        when(userRepository.findByTenantIdAndProviderId(anyLong(), anyString())).thenAnswer(inv -> {
            Long tid = inv.getArgument(0);
            String pid = inv.getArgument(1);
            return world.users.values().stream()
                    .filter(u -> u.getTenant() != null && tid.equals(u.getTenant().getId()))
                    .filter(u -> pid.equals(u.getProviderId()))
                    .findFirst();
        });

        engine = new FederationRulesEngine(userRepository);
    }

    private Tenant tenant(String slug) {
        return world.tenants.computeIfAbsent(slug, s ->
                Tenant.builder().id(ids.getAndIncrement()).slug(s).name(s).enabled(true).build());
    }

    // ---- Fixtures --------------------------------------------------

    @Given("tenant {string} exists for federation tests")
    public void tenantExists(String slug) {
        ensureWired();
        tenant(slug);
    }

    @Given("user {string} exists in tenant {string} for federation tests")
    public void userExists(String email, String slug) {
        Tenant t = tenant(slug);
        User u = User.builder()
                .id(ids.getAndIncrement())
                .tenant(t)
                .email(email)
                .username(email)
                .build();
        world.users.put(slug + "|" + email.toLowerCase(), u);
    }

    @Given("user {string} exists in tenant {string} with providerId {string} for federation tests")
    public void userExistsWithProviderId(String email, String slug, String providerId) {
        Tenant t = tenant(slug);
        User u = User.builder()
                .id(ids.getAndIncrement())
                .tenant(t)
                .email(email)
                .username(email)
                .providerId(providerId)
                .build();
        world.users.put(slug + "|" + email.toLowerCase(), u);
    }

    // ---- Rule setup ------------------------------------------------

    @Given("tenant {string} has no federation matching rules")
    public void tenantHasNoRules(String slug) {
        tenant(slug).setMatchingRules(null);
    }

    @Given("tenant {string} has matching rule strategy {string} on claim {string}")
    public void tenantHasSingleRule(String slug, String strategy, String claim) {
        Map<String, Object> rule = new LinkedHashMap<>();
        rule.put("strategy", strategy);
        rule.put("claim", claim);
        List<Map<String, Object>> rules = new ArrayList<>();
        rules.add(rule);
        tenant(slug).setMatchingRules(rules);
    }

    @Given("tenant {string} has matching rules:")
    public void tenantHasRules(String slug, DataTable table) {
        List<Map<String, Object>> rules = new ArrayList<>();
        for (List<String> row : table.asLists()) {
            Map<String, Object> rule = new LinkedHashMap<>();
            rule.put("strategy", row.get(0));
            rule.put("claim", row.get(1));
            rules.add(rule);
        }
        tenant(slug).setMatchingRules(rules);
    }

    @Given("tenant {string} has claim transform target {string} path {string}")
    public void tenantHasClaimTransform(String slug, String target, String path) {
        Map<String, Object> rule = new LinkedHashMap<>();
        rule.put("target", target);
        rule.put("path", path);
        List<Map<String, Object>> transforms = new ArrayList<>();
        transforms.add(rule);
        tenant(slug).setClaimTransforms(transforms);
    }

    @Given("tenant {string} has claim transform target {string} path {string} when {string}")
    public void tenantHasConditionalTransform(String slug, String target, String path, String condition) {
        Map<String, Object> rule = new LinkedHashMap<>();
        rule.put("target", target);
        rule.put("path", path);
        rule.put("condition", condition);
        List<Map<String, Object>> transforms = new ArrayList<>();
        transforms.add(rule);
        tenant(slug).setClaimTransforms(transforms);
    }

    // ---- Actions ---------------------------------------------------

    @When("the federation engine matches claims for {string}:")
    public void engineMatches(String slug, DataTable table) {
        Map<String, Object> claims = new HashMap<>();
        for (List<String> row : table.asLists()) {
            claims.put(row.get(0), row.get(1));
        }
        matchResult = engine.matchUser(tenant(slug), claims);
    }

    @When("the federation engine transforms claims for {string}:")
    public void engineTransforms(String slug, DataTable table) throws Exception {
        // Single row: | raw | <json string> |
        String rawJson = table.asLists().get(0).get(1);
        Map<String, Object> claims = json.readValue(rawJson, new TypeReference<>() {});
        transformedResult = engine.transformClaims(tenant(slug), claims);
    }

    // ---- Assertions ------------------------------------------------

    @Then("the federation engine returns no match")
    public void engineReturnsNoMatch() {
        assertThat(matchResult).isEmpty();
    }

    @Then("the federation engine returns user {string}")
    public void engineReturnsUser(String email) {
        assertThat(matchResult).isPresent();
        assertThat(matchResult.get().getEmail()).isEqualToIgnoringCase(email);
    }

    @Then("the transformed claim {string} is {string}")
    public void transformedClaimIs(String key, String value) {
        assertThat(transformedResult).containsEntry(key, value);
    }

    @Then("the transformed claim {string} is absent")
    public void transformedClaimAbsent(String key) {
        assertThat(transformedResult).doesNotContainKey(key);
    }
}
