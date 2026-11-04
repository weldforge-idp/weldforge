package tech.cwvermaak.weldforge.bdd;

import io.cucumber.java.en.Given;
import io.cucumber.java.en.Then;
import io.cucumber.java.en.When;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.test.util.ReflectionTestUtils;
import tech.cwvermaak.weldforge.config.security.HmacKeyRing;
import tech.cwvermaak.weldforge.service.JwtService;

import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Steps for the platform HMAC key ring scenarios in
 * {@code epic_e_tokens.feature} (B-JWT-2 / CONF-7.4).
 *
 * <p>The feature file names secrets symbolically ("SECRET-A") because the real
 * values must be 64 bytes for HS512 and a Gherkin scenario is no place for a
 * wall of entropy. {@link #secretFor} expands a name to a fixed, long-enough
 * value, so the scenarios stay readable and the keys stay legal.
 */
public class HmacKeyRingSteps {

    private final Map<String, String> secrets = new HashMap<>();

    private JwtService service;
    private String keptToken;
    private String subjectToken;

    /** Expand a scenario's symbolic name into a 64-byte secret. */
    private String secretFor(String name) {
        return secrets.computeIfAbsent(name, n -> {
            String base = "platform-secret-" + n.toLowerCase().replace("-", "") + "-";
            StringBuilder sb = new StringBuilder(base);
            while (sb.length() < 68) {
                sb.append('x');
            }
            return sb.toString();
        });
    }

    private JwtService serviceWith(String active, String previous) {
        JwtService s = new JwtService();
        ReflectionTestUtils.setField(s, "secret", active);
        ReflectionTestUtils.setField(s, "previousSecrets", previous);
        ReflectionTestUtils.setField(s, "accessExpirationMs", 60_000L);
        ReflectionTestUtils.setField(s, "refreshExpirationMs", 600_000L);
        ReflectionTestUtils.setField(s, "audience", "weldforge");
        return s;
    }

    @Given("the platform signing secret is {string} with no retired keys")
    public void signingSecretWithNoRetiredKeys(String name) {
        service = serviceWith(secretFor(name), "");
    }

    @Given("the platform signing secret is {string} with retired key {string}")
    public void signingSecretWithRetiredKey(String active, String retired) {
        service = serviceWith(secretFor(active), secretFor(retired));
    }

    @Given("a platform token is signed and kept")
    public void aTokenIsSignedAndKept() {
        keptToken = service.generateAccessToken("alice@acme.test", 42L, "acme", false);
    }

    @When("the platform signing secret rotates to {string} retaining {string}")
    public void rotateRetaining(String active, String retained) {
        service = serviceWith(secretFor(active), secretFor(retained));
    }

    @When("the platform signing secret rotates to {string} retaining nothing")
    public void rotateRetainingNothing(String active) {
        service = serviceWith(secretFor(active), "");
    }

    @When("a platform token is signed")
    public void aTokenIsSigned() {
        subjectToken = service.generateAccessToken("alice@acme.test", 42L, "acme", false);
    }

    @When("a platform token is forged naming the active key id")
    public void aForgedTokenNamingTheActiveKid() {
        String activeSecret = (String) ReflectionTestUtils.getField(service, "secret");
        subjectToken = Jwts.builder()
                .header().keyId(HmacKeyRing.keyId(activeSecret)).and()
                .subject("attacker@evil.test")
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + 60_000))
                .signWith(Keys.hmacShaKeyFor(
                        secretFor("FORGERY-KEY").getBytes(StandardCharsets.UTF_8)))
                .compact();
    }

    @When("a platform token is signed without a key id under {string}")
    public void aTokenWithoutKid(String name) {
        subjectToken = Jwts.builder()
                .subject("alice@acme.test")
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + 60_000))
                .signWith(Keys.hmacShaKeyFor(secretFor(name).getBytes(StandardCharsets.UTF_8)))
                .compact();
    }

    @When("an expired platform token is signed under {string}")
    public void anExpiredTokenUnder(String name) {
        // Past the parser's 60-second clock-skew allowance, or it would still
        // be accepted and the scenario would assert nothing.
        subjectToken = Jwts.builder()
                .header().keyId(HmacKeyRing.keyId(secretFor(name))).and()
                .subject("alice@acme.test")
                .issuedAt(new Date(System.currentTimeMillis() - 240_000))
                .expiration(new Date(System.currentTimeMillis() - 120_000))
                .signWith(Keys.hmacShaKeyFor(secretFor(name).getBytes(StandardCharsets.UTF_8)))
                .compact();
    }

    @Then("the platform token verifies")
    public void theTokenVerifies() {
        assertThat(service.isTokenValid(subjectToken)).isTrue();
    }

    @Then("the kept platform token still verifies")
    public void theKeptTokenStillVerifies() {
        assertThat(service.isTokenValid(keptToken)).isTrue();
    }

    @Then("the kept platform token is refused")
    public void theKeptTokenIsRefused() {
        assertThat(service.isTokenValid(keptToken)).isFalse();
    }

    @Then("the platform token is refused")
    public void theTokenIsRefused() {
        assertThat(service.isTokenValid(subjectToken)).isFalse();
    }

    @Then("the platform token verifies against signing secret {string} alone")
    public void verifiesAgainstAlone(String name) {
        assertThat(serviceWith(secretFor(name), "").isTokenValid(subjectToken)).isTrue();
    }

    @Then("the platform token is refused by signing secret {string} alone")
    public void refusedByAlone(String name) {
        assertThat(serviceWith(secretFor(name), "").isTokenValid(subjectToken)).isFalse();
    }

    @Then("verifying the platform token reports that it expired")
    public void reportsExpiry() {
        // Not merely "is refused": the distinction is the point. An earlier
        // draft swallowed every failure while walking the ring, which reported
        // ordinary expiry as a signature mismatch and hid the real cause.
        assertThatThrownBy(() -> service.parse(subjectToken))
                .isInstanceOf(ExpiredJwtException.class);
    }
}
