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

    @Given("the default password policy")
    public void defaultPolicy() {
        service = new PasswordPolicyService(new PasswordPolicyProperties());
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
