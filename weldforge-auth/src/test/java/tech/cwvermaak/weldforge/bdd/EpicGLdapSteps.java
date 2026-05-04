package tech.cwvermaak.weldforge.bdd;

import io.cucumber.java.en.Given;
import io.cucumber.java.en.Then;
import io.cucumber.java.en.When;
import tech.cwvermaak.weldforge.model.LdapProviderType;
import tech.cwvermaak.weldforge.model.Tenant;
import tech.cwvermaak.weldforge.model.TenantLdapProvider;
import tech.cwvermaak.weldforge.model.User;
import tech.cwvermaak.weldforge.repository.TenantLdapProviderRepository;
import tech.cwvermaak.weldforge.repository.UserRepository;
import tech.cwvermaak.weldforge.service.federation.FederationRulesEngine;
import tech.cwvermaak.weldforge.service.ldap.LdapClient;
import tech.cwvermaak.weldforge.service.ldap.LdapUpstreamService;

import java.util.ArrayList;
import java.util.LinkedHashMap;
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
 * Exercises {@link LdapUpstreamService} with a fake {@link LdapClient}
 * so we can assert authentication + provisioning without a real LDAP
 * server. The fake directory is modelled as a small in-memory store.
 */
public class EpicGLdapSteps {

    private final TestWorld world;
    private final AtomicLong ids = new AtomicLong(61000);

    private TenantLdapProviderRepository providerRepository;
    private UserRepository userRepository;
    private FakeLdapDirectory directory;
    private LdapUpstreamService service;

    private final Map<Long, List<TenantLdapProvider>> providersByTenant = new LinkedHashMap<>();

    private Optional<User> lastResult;

    public EpicGLdapSteps(TestWorld world) {
        this.world = world;
    }

    @SuppressWarnings("unchecked")
    private void ensureWired() {
        if (service != null) return;

        providerRepository = mock(TenantLdapProviderRepository.class);
        userRepository = mock(UserRepository.class);
        directory = new FakeLdapDirectory();

        when(providerRepository.findByTenantIdAndEnabledTrue(anyLong())).thenAnswer(inv ->
                providersByTenant.getOrDefault(inv.<Long>getArgument(0), List.of()).stream()
                        .filter(TenantLdapProvider::isEnabled)
                        .toList());

        when(userRepository.findByTenantIdAndEmailIgnoreCase(anyLong(), anyString())).thenAnswer(inv -> {
            Long tid = inv.getArgument(0);
            String email = ((String) inv.getArgument(1)).toLowerCase();
            return world.users.values().stream()
                    .filter(u -> u.getTenant() != null && tid.equals(u.getTenant().getId()))
                    .filter(u -> u.getEmail() != null && u.getEmail().equalsIgnoreCase(email))
                    .findFirst();
        });
        when(userRepository.findByTenantIdAndUsernameIgnoreCase(anyLong(), anyString())).thenAnswer(inv -> {
            Long tid = inv.getArgument(0);
            String name = ((String) inv.getArgument(1)).toLowerCase();
            return world.users.values().stream()
                    .filter(u -> u.getTenant() != null && tid.equals(u.getTenant().getId()))
                    .filter(u -> u.getUsername() != null && u.getUsername().equalsIgnoreCase(name))
                    .findFirst();
        });
        when(userRepository.save(any(User.class))).thenAnswer(inv -> {
            User u = inv.getArgument(0);
            if (u.getId() == null) u.setId(ids.getAndIncrement());
            String key = u.getTenant().getSlug() + "|" + u.getEmail().toLowerCase();
            world.users.put(key, u);
            return u;
        });

        // Federation engine runs with an empty user repo — its match()
        // returns empty when no matching_rules are configured, which is
        // exactly what we want here.
        FederationRulesEngine engine = new FederationRulesEngine(mock(UserRepository.class));
        service = new LdapUpstreamService(providerRepository, directory, userRepository, engine);
    }

    private Tenant tenant(String slug) {
        return world.tenants.computeIfAbsent(slug, s ->
                Tenant.builder().id(ids.getAndIncrement()).slug(s).name(s).enabled(true).build());
    }

    // ---- Fixtures --------------------------------------------------

    @Given("tenant {string} exists for LDAP tests")
    public void tenantExists(String slug) {
        ensureWired();
        tenant(slug);
    }

    @Given("tenant {string} has an LDAP provider {string} at {string}")
    public void tenantHasLdap(String slug, String name, String url) {
        addProvider(slug, name, url, LdapProviderType.LDAP, "(uid={0})", true);
    }

    @Given("tenant {string} has a disabled LDAP provider {string} at {string}")
    public void tenantHasDisabledLdap(String slug, String name, String url) {
        addProvider(slug, name, url, LdapProviderType.LDAP, "(uid={0})", false);
    }

    @Given("tenant {string} has an AD provider {string} at {string}")
    public void tenantHasAd(String slug, String name, String url) {
        addProvider(slug, name, url, LdapProviderType.ACTIVE_DIRECTORY,
                "(|(userPrincipalName={0})(sAMAccountName={0}))", true);
    }

    private void addProvider(String slug, String name, String url, LdapProviderType type,
                             String filter, boolean enabled) {
        Tenant t = tenant(slug);
        TenantLdapProvider p = TenantLdapProvider.builder()
                .id(ids.getAndIncrement())
                .tenant(t)
                .name(name)
                .providerType(type)
                .url(url)
                .userBaseDn("ou=users,dc=acme,dc=test")
                .userSearchFilter(filter)
                .emailAttribute("mail")
                .nameAttribute("cn")
                .usernameAttribute("uid")
                .enabled(enabled)
                .build();
        providersByTenant.computeIfAbsent(t.getId(), k -> new ArrayList<>()).add(p);
    }

    @Given("the LDAP directory has user {string} with password {string} and name {string}")
    public void directoryHasUser(String email, String password, String name) {
        FakeLdapDirectory.Entry e = new FakeLdapDirectory.Entry();
        e.dn = "uid=" + email + ",ou=users,dc=acme,dc=test";
        e.password = password;
        e.attributes.put("mail", email);
        e.attributes.put("cn", name);
        e.attributes.put("uid", email);
        directory.entries.add(e);
    }

    @Given("the AD directory has user with UPN {string} sAMAccountName {string} password {string}")
    public void adDirectoryHas(String upn, String sam, String password) {
        FakeLdapDirectory.Entry e = new FakeLdapDirectory.Entry();
        e.dn = "CN=" + sam + ",OU=users,DC=corp,DC=acme,DC=test";
        e.password = password;
        e.attributes.put("userPrincipalName", upn);
        e.attributes.put("sAMAccountName", sam);
        e.attributes.put("mail", upn);
        e.attributes.put("cn", sam);
        e.attributes.put("uid", sam);
        directory.entries.add(e);
    }

    // ---- Actions ---------------------------------------------------

    @When("the LDAP upstream authenticates user {string} with password {string}")
    public void authenticate(String username, String password) {
        lastResult = service.authenticate(tenant("acme"), username, password);
    }

    // ---- Assertions ------------------------------------------------

    @Then("the LDAP upstream returns no user")
    public void returnsNoUser() {
        assertThat(lastResult).isEmpty();
    }

    @Then("the LDAP upstream returns user {string}")
    public void returnsUser(String email) {
        assertThat(lastResult).isPresent();
        assertThat(lastResult.get().getEmail()).isEqualToIgnoringCase(email);
    }

    @Then("the provisioned user has provider {string}")
    public void providerIs(String provider) {
        assertThat(lastResult.get().getProvider().name()).isEqualTo(provider);
    }

    @Then("the provisioned user has name {string}")
    public void nameIs(String name) {
        assertThat(lastResult.get().getName()).isEqualTo(name);
    }

    @Then("exactly {int} local user exists for {string}")
    public void userCount(int expected, String email) {
        long count = world.users.values().stream()
                .filter(u -> u.getEmail() != null && u.getEmail().equalsIgnoreCase(email))
                .count();
        assertThat(count).isEqualTo(expected);
    }

    // ---- Fake LDAP directory --------------------------------------

    static class FakeLdapDirectory implements LdapClient {
        static class Entry {
            String dn;
            String password;
            final Map<String, Object> attributes = new LinkedHashMap<>();
        }
        final List<Entry> entries = new ArrayList<>();

        @Override
        public Optional<LdapAttributes> authenticate(TenantLdapProvider provider, String username, String password) {
            // Naive filter match: extract attributes named in the filter
            // between '(' and '={0})'. Works for both (uid={0}) and
            // (|(userPrincipalName={0})(sAMAccountName={0})).
            List<String> attrs = extractFilterAttributes(provider.getUserSearchFilter());
            for (Entry e : entries) {
                boolean hit = attrs.stream().anyMatch(a -> username.equalsIgnoreCase(String.valueOf(e.attributes.get(a))));
                if (!hit) continue;
                if (!e.password.equals(password)) return Optional.empty();
                return Optional.of(new LdapAttributes(e.dn, new LinkedHashMap<>(e.attributes)));
            }
            return Optional.empty();
        }

        @Override
        public boolean testConnection(TenantLdapProvider provider) {
            return true;
        }

        private static List<String> extractFilterAttributes(String filter) {
            List<String> out = new ArrayList<>();
            int i = 0;
            while (i < filter.length()) {
                int open = filter.indexOf('(', i);
                if (open < 0) break;
                int eq = filter.indexOf('=', open);
                if (eq < 0) break;
                String attr = filter.substring(open + 1, eq);
                // Strip leading boolean operators like |, &, !.
                if (!attr.isEmpty() && "|&!".indexOf(attr.charAt(0)) >= 0) {
                    i = open + 1;
                    continue;
                }
                out.add(attr);
                i = eq + 1;
            }
            return out;
        }
    }
}
