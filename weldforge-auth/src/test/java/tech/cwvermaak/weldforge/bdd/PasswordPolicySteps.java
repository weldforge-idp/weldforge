package tech.cwvermaak.weldforge.bdd;

import io.cucumber.java.en.Given;
import io.cucumber.java.en.Then;
import io.cucumber.java.en.When;
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
