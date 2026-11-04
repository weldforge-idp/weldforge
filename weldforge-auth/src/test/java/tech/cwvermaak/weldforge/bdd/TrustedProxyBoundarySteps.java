package tech.cwvermaak.weldforge.bdd;

import io.cucumber.java.AfterAll;
import io.cucumber.java.BeforeAll;
import io.cucumber.java.en.Given;
import io.cucumber.java.en.Then;
import io.cucumber.java.en.When;
import tech.cwvermaak.weldforge.config.security.TrustedProxyHarness;

import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Steps for {@code trusted_proxy_boundary.feature} (B-AUTH-1).
 *
 * <p>These drive a real Tomcat with a real {@code RemoteIpValve} configured
 * from the shipped {@code application.yml} — see {@link TrustedProxyHarness}
 * for why nothing less will do. The scenarios therefore assert the behaviour
 * of the configuration that deploys, not of a stand-in.
 */
public class TrustedProxyBoundarySteps {

    /**
     * One Tomcat for the whole Cucumber run, closed when it ends. Tomcat's
     * threads are not daemons, so a harness left open holds the surefire fork
     * until its 180s exit timeout kills it.
     */
    private static TrustedProxyHarness app;

    private String clientAddress;
    private String scheme;

    @BeforeAll
    public static void startServer() {
        app = TrustedProxyHarness.start();
    }

    @AfterAll
    public static void stopServer() {
        if (app != null) {
            app.close();
            app = null;
        }
    }

    @Given("the server trusts only its own proxy hops")
    public void theServerTrustsOnlyItsOwnProxyHops() {
        assertThat(app.internalProxies()).isNotEqualTo(".*");
    }

    @When("a request arrives forwarded as {string}")
    public void aRequestArrivesForwardedAs(String chain) {
        clientAddress = app.remoteAddrSeenBy("X-Forwarded-For", chain);
    }

    @When("a request arrives with nothing forwarded")
    public void aRequestArrivesWithNothingForwarded() {
        clientAddress = app.remoteAddrSeenBy();
    }

    @When("a request arrives forwarded as HTTPS")
    public void aRequestArrivesForwardedAsHttps() {
        scheme = app.schemeSeenBy("X-Forwarded-Proto", "https");
    }

    @Then("the client address is {string}")
    public void theClientAddressIs(String expected) {
        assertThat(clientAddress).isEqualTo(expected);
    }

    @Then("the forged entry {string} is not the client address")
    public void theForgedEntryIsNotTheClientAddress(String forged) {
        assertThat(clientAddress).isNotEqualTo(forged);
    }

    @Then("the client address is the connecting peer")
    public void theClientAddressIsTheConnectingPeer() {
        assertThat(clientAddress).isEqualTo("127.0.0.1");
    }

    @Then("the server treats the request as HTTPS")
    public void theServerTreatsTheRequestAsHttps() {
        // Not cosmetic: the OIDC issuer, the authorize and token endpoints and
        // the discovery document are built from this scheme. If the boundary
        // stopped matching the real proxy hop they would advertise http://<pod>.
        assertThat(scheme).isEqualTo("https");
    }

    @Then("the configured trust boundary is not a wildcard")
    public void theConfiguredTrustBoundaryIsNotAWildcard() {
        assertThat(app.internalProxies())
                .as("server.tomcat.remoteip.internal-proxies")
                .isNotEqualTo(".*")
                .isNotEqualTo(".+");
    }

    @Then("a public address is not treated as one of our proxies")
    public void aPublicAddressIsNotTreatedAsOneOfOurProxies() {
        Pattern boundary = Pattern.compile(app.internalProxies());
        assertThat(boundary.matcher(TrustedProxyHarness.REAL_CLIENT).matches()).isFalse();
        assertThat(boundary.matcher(TrustedProxyHarness.SPOOFED).matches()).isFalse();
    }
}
