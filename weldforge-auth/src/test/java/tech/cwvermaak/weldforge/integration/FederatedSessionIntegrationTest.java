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
                "default", "federated@test.com", "google", request, response);

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
                "default", "nobody-here@test.com", "google", new MockHttpServletRequest(),
                new MockHttpServletResponse());

        assertThat(session).isEmpty();
    }

    @Test
    @DisplayName("case does not matter: the provider may return a differently cased address")
    void addressIsMatchedCaseInsensitively() {
        Optional<AuthResponseDto> session = authService.issueFederatedSession(
                "default", "Federated@Test.com", "google", new MockHttpServletRequest(),
                new MockHttpServletResponse());

        assertThat(session).isPresent();
    }
}
