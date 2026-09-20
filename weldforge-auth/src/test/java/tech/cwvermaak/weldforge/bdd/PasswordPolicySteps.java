package tech.cwvermaak.weldforge.bdd;

import io.cucumber.java.en.Given;
import io.cucumber.java.en.Then;
import io.cucumber.java.en.When;
import tech.cwvermaak.weldforge.model.Tenant;
import tech.cwvermaak.weldforge.service.security.PasswordPolicyProperties;
import tech.cwvermaak.weldforge.service.security.PasswordPolicyService;
import tech.cwvermaak.weldforge.service.security.PasswordPolicyViolation;

import static org.assertj.core.api.Assertions.assertThat;

public class PasswordPolicySteps {

    private final TestWorld world;
    private PasswordPolicyService service;

    public PasswordPolicySteps(TestWorld world) {
        this.world = world;
    }

    private final PasswordPolicyProperties properties = new PasswordPolicyProperties();
    /** A stand-in corpus: the passwords every breach list contains. */
    private final java.util.Set<String> breachCorpus = java.util.Set.of(
            "password1234", "Password1234!", "qwertyuiop123");
    /** What the screen was given, to prove the password itself never left. */
    private final java.util.List<String> sentToCorpus = new java.util.ArrayList<>();

    @Given("the default password policy")
    public void defaultPolicy() {
        // The real k-anonymity screen, with the network replaced by a corpus
        // lookup keyed on the prefix it would have sent.
        var screen = new tech.cwvermaak.weldforge.service.security.PwnedPasswordsScreenTestAccess(
                breachCorpus, sentToCorpus).screen();
        service = new PasswordPolicyService(properties, screen);
    }

    @Given("the deployment sets app.security.password.require-symbol=true")
    public void requireSymbol() {
        properties.setRequireSymbol(true);
        defaultPolicy();
    }

    @When("a user registers with a password present in the breach corpus")
    public void registersWithBreached() {
        iValidate("password1234");
    }

    @Then("the password is never transmitted in full to any third party")
    public void neverTransmittedInFull() {
        assertThat(sentToCorpus).isNotEmpty();
        assertThat(sentToCorpus).allSatisfy(sent -> {
            assertThat(sent).hasSize(5);
            assertThat(breachCorpus).noneMatch(sent::contains);
        });
    }

    @When("I validate {string}")
    public void iValidate(String password) {
        try {
            service.validate(password);
            world.lastResult = "accepted";
        } catch (PasswordPolicyViolation e) {
            world.lastError = e;
        }
    }

    // ---- Per-tenant overrides -----------------------------------------

    /** The tenant under test; its passwordPolicy map is built up step by step. */
    private Tenant tenant;

    private Tenant tenantNamed(String slug) {
        if (tenant == null || !slug.equals(tenant.getSlug())) {
            tenant = new Tenant();
            tenant.setSlug(slug);
            tenant.setPasswordPolicy(new java.util.HashMap<>());
        }
        return tenant;
    }

    private void override(String slug, String key, Object value) {
        Tenant t = tenantNamed(slug);
        java.util.Map<String, Object> p = new java.util.HashMap<>(t.getPasswordPolicy());
        p.put(key, value);
        t.setPasswordPolicy(p);
    }

    @Given("the tenant {string} requires at least {int} characters")
    public void tenantRequiresMinLength(String slug, int min) {
        override(slug, "minLength", min);
    }

    @Given("the tenant {string} requires a symbol")
    public void tenantRequiresSymbol(String slug) {
        override(slug, "requireSymbol", true);
    }

    @Given("the tenant {string} does not require a symbol")
    public void tenantDoesNotRequireSymbol(String slug) {
        // Stored, but inert against a deployment that does require one — the
        // scenario using this asserts exactly that.
        override(slug, "requireSymbol", false);
    }

    @Given("the tenant {string} has no password policy of its own")
    public void tenantInherits(String slug) {
        tenant = new Tenant();
        tenant.setSlug(slug);
        tenant.setPasswordPolicy(null);
    }

    @When("I validate {string} for that tenant")
    public void iValidateForTenant(String password) {
        try {
            service.validate(password, tenant);
            world.lastResult = "accepted";
        } catch (PasswordPolicyViolation e) {
            world.lastError = e;
        }
    }

    @Then("the password is accepted")
    public void accepted() {
        assertThat(world.lastError).isNull();
        assertThat(world.lastResult).isEqualTo("accepted");
    }

    @Then("the password is rejected")
    public void rejected() {
        assertThat(world.lastError).isInstanceOf(PasswordPolicyViolation.class);
    }

    @Then("the rejection mentions {string}")
    public void rejectionMentions(String needle) {
        assertThat(world.lastError).isInstanceOf(PasswordPolicyViolation.class);
        PasswordPolicyViolation v = (PasswordPolicyViolation) world.lastError;
        assertThat(v.getReasons())
                .anyMatch(r -> r.contains(needle));
    }
}
