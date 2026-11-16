package tech.cwvermaak.weldforge.integration;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import tech.cwvermaak.weldforge.config.tenant.TenantContext;
import tech.cwvermaak.weldforge.model.AuthProvider;
import tech.cwvermaak.weldforge.model.Tenant;
import tech.cwvermaak.weldforge.model.User;
import tech.cwvermaak.weldforge.model.dto.AuthResponseDto;
import tech.cwvermaak.weldforge.repository.TenantRepository;
import tech.cwvermaak.weldforge.repository.UserRepository;
import tech.cwvermaak.weldforge.service.AuthService;

import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * A social sign-in is finished by a Spring Security success handler, which
 * runs in the filter chain. Nothing has opened a persistence context out
 * there: the open-in-view interceptor this application leaves enabled belongs
 * to the DispatcherServlet and has not run yet, and will not run for a request
 * the security filters complete themselves.
 *
 * <p>That is the whole point of these tests, and the reason none of them is
 * {@code @Transactional}: a test transaction would supply the session the real
 * caller does not have, and the bug this covers would pass. On 2026-10-11 a
 * correct Google sign-in for {@code counteract-studios} returned Spring's
 * whitelabel 500, from {@code LazyInitializationException} on
 * {@code user.getTenant().getRefreshTtlMs()} -- the user had been loaded in
 * the handler and was detached before the token service ever saw it.
 */
@SpringBootTest
@Testcontainers
@EnabledIfSystemProperty(named = "tests.integration", matches = "true")
@DisplayName("Federated session: minted from outside any persistence context")
class FederatedSessionIntegrationTest {

    @Container
    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:16-alpine")
            .withDatabaseName("weldforge_test")
            .withUsername("test")
            .withPassword("test");

    @DynamicPropertySource
    static void datasource(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url",      POSTGRES::getJdbcUrl);
        registry.add("spring.datasource.username", POSTGRES::getUsername);
        registry.add("spring.datasource.password", POSTGRES::getPassword);
        registry.add("app.crypto.secret", () -> "ci-only-crypto-secret-0123456789abcdef");
        registry.add("spring.jpa.hibernate.ddl-auto", () -> "validate");
        registry.add("app.security.password.breach-check.enabled", () -> "false");
    }

    @BeforeAll
    static void dockerOrSkip() {
        assumeTrue(System.getProperty("tests.integration", "false").equals("true"),
                "Set -Dtests.integration=true to enable Postgres integration tests");
    }

    @Autowired private AuthService authService;
    @Autowired private TenantRepository tenantRepository;
    @Autowired private UserRepository userRepository;
    @Autowired private tech.cwvermaak.weldforge.repository.TenantSocialProviderRepository providerRepository;
    @Autowired private tech.cwvermaak.weldforge.service.JwtService jwtService;

    private Tenant tenant;

    @BeforeEach
    void seed() {
        tenant = tenantRepository.findBySlug("default").orElseThrow();
        TenantContext.set("default", tenant.getId(), true);

        if (userRepository.findByTenant_SlugAndEmailIgnoreCase("default", "federated@test.com").isEmpty()) {
            userRepository.save(User.builder()
                    .tenant(tenant)
                    .username("federated-user")
                    .email("federated@test.com")
                    .provider(AuthProvider.GOOGLE)
                    .providerId("google-federated-user")
                    .emailVerified(true)
                    .active(true)
                    .build());
        }
    }

    @Test
    @DisplayName("mints a session with no transaction open, the way the success handler calls it")
    void mintsASessionOutsideAnyTransaction() {
        // Guards the test itself. If a future change makes the suite
        // transactional by default this fails loudly rather than quietly
        // stopping to cover the thing it was written for.
        assertThat(TransactionSynchronizationManager.isActualTransactionActive())
                .as("the caller is a security filter; it has no transaction and no open session")
                .isFalse();

        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();

        Optional<AuthResponseDto> session = authService.issueFederatedSession(
                "default", "federated@test.com", "google", null, request, response);

        assertThat(session).isPresent();
        assertThat(session.get().getToken()).isNotBlank();

        // getRefreshTtlMs() on the tenant is the call that threw. Both refresh
        // cookies carry its value, so their presence is the assertion.
        List<String> cookies = response.getHeaders("Set-Cookie");
        assertThat(cookies).anyMatch(c -> c.startsWith("wf_refresh_default="));
        assertThat(cookies).anyMatch(c -> c.startsWith("refresh_token="));
    }

    @Test
    @DisplayName("an address with no user row is empty, not an exception and not a session")
    void unknownAddressIsEmpty() {
        Optional<AuthResponseDto> session = authService.issueFederatedSession(
                "default", "nobody-here@test.com", "google", null, new MockHttpServletRequest(),
                new MockHttpServletResponse());

        assertThat(session).isEmpty();
    }

    @Test
    @DisplayName("case does not matter: the provider may return a differently cased address")
    void addressIsMatchedCaseInsensitively() {
        Optional<AuthResponseDto> session = authService.issueFederatedSession(
                "default", "Federated@Test.com", "google", null, new MockHttpServletRequest(),
                new MockHttpServletResponse());

        assertThat(session).isPresent();
    }

    // ---- V71: an asserted amr, and the gate that makes it mean anything ----

    /**
     * Put a GOOGLE row on the tenant with the given assertion. Written through
     * the repository rather than the admin API on purpose: these tests are
     * about what the TOKEN carries, and the API's refusals are covered as unit
     * tests in AssertedAmrPolicyTest. The last case below is the one that can
     * only be reached this way.
     */
    private void providerRow(String assertedAmr, String requiredHd) {
        var existing = providerRepository.findByTenantIdAndProvider(
                tenant.getId(), tech.cwvermaak.weldforge.model.SocialProviderType.GOOGLE);
        var row = existing.orElseGet(() ->
                tech.cwvermaak.weldforge.model.TenantSocialProvider.builder()
                        .tenant(tenant)
                        .provider(tech.cwvermaak.weldforge.model.SocialProviderType.GOOGLE)
                        .clientId("test-client-id")
                        .clientSecret("test-client-secret")
                        .enabled(true)
                        .build());
        row.setAssertedAmr(assertedAmr);
        row.setRequiredHd(requiredHd);
        providerRepository.saveAndFlush(row);
    }

    private io.jsonwebtoken.Claims claimsOf(String token) {
        return jwtService.parse(token);
    }

    private String sessionToken(String hd) {
        MockHttpServletResponse response = new MockHttpServletResponse();
        Optional<AuthResponseDto> session = authService.issueFederatedSession(
                "default", "federated@test.com", "google", hd,
                new MockHttpServletRequest(), response);
        assertThat(session).isPresent();
        return session.get().getToken();
    }

    @Test
    @DisplayName("no provider row: the session carries no amr claim, exactly as before V71")
    void noProviderRowAssertsNothing() {
        providerRepository.findByTenantIdAndProvider(
                        tenant.getId(), tech.cwvermaak.weldforge.model.SocialProviderType.GOOGLE)
                .ifPresent(providerRepository::delete);

        var claims = claimsOf(sessionToken(null));

        // The default-off regression guard. If this goes red, the feature has
        // leaked into tenants that did not ask for it.
        assertThat(claims.get("amr")).isNull();
    }

    @Test
    @DisplayName("a row with no assertion carries no amr claim")
    void rowWithoutAssertionAssertsNothing() {
        providerRow(null, null);

        assertThat(claimsOf(sessionToken(null)).get("amr")).isNull();
    }

    @Test
    @DisplayName("an asserted hwk reaches the token, and idp names the provider")
    @SuppressWarnings("unchecked")
    void assertedHwkReachesTheToken() {
        providerRow("hwk mfa", "test.example");

        var claims = claimsOf(sessionToken("test.example"));

        assertThat((List<String>) claims.get("amr")).containsExactlyInAnyOrder("hwk", "mfa");
        // Truthful whether or not anything is asserted: it lets a relying party
        // make its own decision instead of trusting ours.
        assertThat(claims.get("idp")).isEqualTo("default-google");
    }

    @Test
    @DisplayName("an assertion with no phishing-resistant factor needs no gate")
    @SuppressWarnings("unchecked")
    void otpNeedsNoGate() {
        providerRow("otp mfa", null);

        assertThat((List<String>) claimsOf(sessionToken(null)).get("amr"))
                .containsExactlyInAnyOrder("otp", "mfa");
    }

    @Test
    @DisplayName("a stored hwk with no hosted-domain gate asserts NOTHING, however it got there")
    void ungatedStoredAssertionIsRefusedAtIssueTime() {
        // The API refuses to store this (AssertedAmrPolicyTest covers that),
        // but a row can also arrive by hand -- a restore, a psql session, a
        // migration written in a hurry. Validating only at write time would
        // make the gate a property of one code path rather than of the
        // feature, and the one thing this must never do is assert phishing
        // resistance for an upstream that is not gated. So it is enforced
        // again here, and fails closed: no amr at all.
        providerRow("hwk", null);

        assertThat(claimsOf(sessionToken(null)).get("amr"))
                .as("an invalid row asserts nothing rather than asserting hwk")
                .isNull();
    }

    @Test
    @DisplayName("idp is present on a federated session even when nothing is asserted")
    void idpIsUnconditional() {
        providerRow(null, null);

        assertThat(claimsOf(sessionToken(null)).get("idp")).isEqualTo("default-google");
    }

    // ---- 2026-11-15: the tenant's account gates apply to a social sign-in ----
    //
    // The provider proves who the person is; it does not decide whether this
    // tenant lets them in. A deactivated or locked account, and an account
    // with a second factor enrolled, all received a full session here.

    @Autowired private tech.cwvermaak.weldforge.repository.MfaFactorRepository mfaFactorRepository;
    @Autowired private tech.cwvermaak.weldforge.repository.TenantMfaPolicyRepository mfaPolicyRepository;

    private User federatedUser(Tenant t, java.util.function.Consumer<User.UserBuilder> tweak) {
        String tag = java.util.UUID.randomUUID().toString().substring(0, 8);
        User.UserBuilder b = User.builder()
                .tenant(t)
                .username("fed-" + tag)
                .email("fed-" + tag + "@test.com")
                .provider(AuthProvider.GOOGLE)
                .providerId("google-" + tag)
                .emailVerified(true)
                .active(true);
        tweak.accept(b);
        return userRepository.save(b.build());
    }

    private static boolean issuedSessionCookies(MockHttpServletResponse response) {
        return response.getHeaders("Set-Cookie").stream()
                .anyMatch(c -> c.startsWith("wf_refresh_") || c.startsWith("refresh_token=")
                        || c.startsWith("wf_session="));
    }

    @Test
    @DisplayName("a deactivated account gets no session from a social sign-in")
    void inactiveAccountIsRefused() {
        User u = federatedUser(tenant, b -> b.active(false));
        MockHttpServletResponse response = new MockHttpServletResponse();

        assertThatThrownBy(() -> authService.issueFederatedSession(
                "default", u.getEmail(), "google", null, new MockHttpServletRequest(), response))
                .isInstanceOf(RuntimeException.class)
                .extracting("code").isEqualTo("account_unavailable");
        assertThat(issuedSessionCookies(response)).isFalse();
    }

    @Test
    @DisplayName("a locked account gets no session from a social sign-in")
    void lockedAccountIsRefused() {
        User u = federatedUser(tenant, b -> b.lockedUntil(java.time.LocalDateTime.now().plusMinutes(10)));
        MockHttpServletResponse response = new MockHttpServletResponse();

        assertThatThrownBy(() -> authService.issueFederatedSession(
                "default", u.getEmail(), "google", null, new MockHttpServletRequest(), response))
                .isInstanceOf(RuntimeException.class)
                .extracting("code").isEqualTo("account_unavailable");
        assertThat(issuedSessionCookies(response)).isFalse();
    }

    @Test
    @DisplayName("an account with a second factor gets an MFA challenge, not a session")
    void enrolledFactorGetsAChallenge() {
        User u = federatedUser(tenant, b -> {});
        mfaFactorRepository.save(tech.cwvermaak.weldforge.model.MfaFactor.builder()
                .user(u).type(tech.cwvermaak.weldforge.model.MfaFactorType.TOTP)
                .label("phone").totpSecretEnc("not-used-here").verified(true).enabled(true).build());
        MockHttpServletResponse response = new MockHttpServletResponse();

        Optional<AuthResponseDto> outcome = authService.issueFederatedSession(
                "default", u.getEmail(), "google", null, new MockHttpServletRequest(), response);

        assertThat(outcome).isPresent();
        assertThat(outcome.get().isMfaRequired()).isTrue();
        assertThat(outcome.get().getMfaChallengeToken()).isNotBlank();
        assertThat(outcome.get().getToken()).as("no access token before the second factor").isNull();
        assertThat(outcome.get().getAvailableFactors())
                .contains(tech.cwvermaak.weldforge.model.MfaFactorType.TOTP);
        assertThat(issuedSessionCookies(response)).isFalse();
    }

    @Test
    @DisplayName("a tenant that requires MFA enrolment refuses a social sign-in from an unenrolled account")
    void requiredEnrolmentIsRefused() {
        String slug = "fed-mfa-" + java.util.UUID.randomUUID().toString().substring(0, 6);
        Tenant strict = tenantRepository.save(Tenant.builder().slug(slug).name(slug).displayName(slug).build());
        mfaPolicyRepository.save(tech.cwvermaak.weldforge.model.TenantMfaPolicy.builder()
                .tenant(strict)
                .enforcement(tech.cwvermaak.weldforge.model.TenantMfaPolicy.Enforcement.REQUIRED)
                .gracePeriodDays(0)
                .build());
        User u = federatedUser(strict, b -> {});
        MockHttpServletResponse response = new MockHttpServletResponse();

        assertThatThrownBy(() -> authService.issueFederatedSession(
                slug, u.getEmail(), "google", null, new MockHttpServletRequest(), response))
                .isInstanceOf(RuntimeException.class)
                .extracting("code").isEqualTo("mfa_enrollment_required");
        assertThat(issuedSessionCookies(response)).isFalse();
    }

    @Test
    @DisplayName("a social sign-in does not reset the password-failure counter")
    void failureCounterIsNotReset() {
        User u = federatedUser(tenant, b -> b.failedLoginAttempts(3));

        authService.issueFederatedSession("default", u.getEmail(), "google", null,
                new MockHttpServletRequest(), new MockHttpServletResponse());

        assertThat(userRepository.findById(u.getId()).orElseThrow().getFailedLoginAttempts()).isEqualTo(3);
    }
}
