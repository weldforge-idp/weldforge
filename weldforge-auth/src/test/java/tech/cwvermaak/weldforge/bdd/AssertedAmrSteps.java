package tech.cwvermaak.weldforge.bdd;

import io.cucumber.java.en.Then;
import io.cucumber.java.en.When;
import tech.cwvermaak.weldforge.service.EmailDomainPolicy;
import tech.cwvermaak.weldforge.service.security.AssertedAmrPolicy;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Steps for the trusted-social-sign-in scenarios in
 * {@code epic_c_federation.feature}.
 *
 * <p>Both policies under test are pure functions over strings, deliberately,
 * so these steps need no database and no Spring context — the rule deciding how
 * strong a federated session may claim to be is worth being able to read and
 * exercise on its own.
 */
public class AssertedAmrSteps {

    private IllegalArgumentException refusal;
    private boolean gateSatisfied;

    @When("the asserted amr {string} with required hosted domain {string} is validated")
    public void validate(String assertedAmr, String requiredHd) {
        refusal = null;
        try {
            AssertedAmrPolicy.validate(assertedAmr, requiredHd);
        } catch (IllegalArgumentException e) {
            refusal = e;
        }
    }

    @Then("the asserted amr configuration is accepted")
    public void accepted() {
        assertThat(refusal)
                .as("expected the configuration to be accepted")
                .isNull();
    }

    @Then("the asserted amr configuration is refused because of {string}")
    public void refused(String reason) {
        assertThat(refusal)
                .as("expected the configuration to be refused")
                .isNotNull();
        assertThat(refusal.getMessage()).contains(reason);
    }

    @When("a sign-in with hosted domain {string} is checked against required {string}")
    public void checkHostedDomain(String hostedDomain, String required) {
        gateSatisfied = EmailDomainPolicy.satisfiesRequiredHostedDomain(
                EmailDomainPolicy.parse(required), hostedDomain);
    }

    @When("a sign-in with no hosted domain is checked against required {string}")
    public void checkAbsentHostedDomain(String required) {
        gateSatisfied = EmailDomainPolicy.satisfiesRequiredHostedDomain(
                EmailDomainPolicy.parse(required), null);
    }

    @Then("the hosted-domain gate is satisfied")
    public void satisfied() {
        assertThat(gateSatisfied).isTrue();
    }

    @Then("the hosted-domain gate is not satisfied")
    public void notSatisfied() {
        assertThat(gateSatisfied).isFalse();
    }
}
