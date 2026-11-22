package tech.cwvermaak.weldforge.integration;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.saml2.provider.service.authentication.DefaultSaml2AuthenticatedPrincipal;
import org.springframework.security.saml2.provider.service.authentication.Saml2Authentication;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import tech.cwvermaak.weldforge.config.saml.SamlUserProvisioningSuccessHandler;
import tech.cwvermaak.weldforge.model.AuthProvider;
import tech.cwvermaak.weldforge.model.MfaFactor;
import tech.cwvermaak.weldforge.model.MfaFactorType;
import tech.cwvermaak.weldforge.model.ScimGroup;
import tech.cwvermaak.weldforge.model.Tenant;
import tech.cwvermaak.weldforge.model.User;
import tech.cwvermaak.weldforge.repository.MfaFactorRepository;
import tech.cwvermaak.weldforge.repository.ScimGroupRepository;
import tech.cwvermaak.weldforge.repository.TenantRepository;
import tech.cwvermaak.weldforge.repository.UserRepository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Security review 2026-11-15 (Proboulos WF-3): a sign-in at a tenant's
 * upstream SAML IdP provisioned the account and then went to Spring's default
 * success handler. Under the stateless policy that issued no session at all,
 * and none of the account gates ran.
 *
 * <p>Not {@code @Transactional}, deliberately: the real caller is a security
 * filter with no persistence context, and a test transaction would hide the
 * lazy-loading failure the old provisioning code swallowed.
 */
@SpringBootTest
@Testcontainers
@EnabledIfSystemProperty(named = "tests.integration", matches = "true")
@DisplayName("Upstream SAML sign-in ends in a gated WeldForge session")
class SamlUpstreamSignInIntegrationTest {

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

    @Autowired SamlUserProvisioningSuccessHandler handler;
    @Autowired TenantRepository tenants;
    @Autowired UserRepository users;
    @Autowired MfaFactorRepository factors;
    @Autowired ScimGroupRepository groups;
    @Autowired org.springframework.jdbc.core.JdbcTemplate jdbc;

    private Tenant tenant() {
        return tenants.findBySlug("default").orElseThrow();
    }

    private static String address() {
        return "saml-" + UUID.randomUUID().toString().substring(0, 8) + "@idp.example";
    }

    private User existing(String email, java.util.function.Consumer<User.UserBuilder> tweak) {
        User.UserBuilder b = User.builder()
                .tenant(tenant())
                .username(email)
                .email(email)
                .name("Original Name")
                .provider(AuthProvider.SAML)
                .providerId(email)
                .emailVerified(true)
                .active(true);
        tweak.accept(b);
        return users.save(b.build());
    }

    /** Runs the handler the way Spring's SAML filter does, after a valid assertion. */
    private MockHttpServletResponse signIn(String email, Map<String, List<Object>> extra) throws Exception {
        assertThat(TransactionSynchronizationManager.isActualTransactionActive())
                .as("the real caller is a security filter with no transaction").isFalse();
        Map<String, List<Object>> attrs = new java.util.HashMap<>(extra);
        attrs.put("email", List.of(email));
        attrs.putIfAbsent("name", List.of("From The IdP"));
        DefaultSaml2AuthenticatedPrincipal principal = new DefaultSaml2AuthenticatedPrincipal(email, attrs);
        principal.setRelyingPartyRegistrationId("default-saml-okta");
        Saml2Authentication auth = new Saml2Authentication(principal, "<Response/>", List.of());

        MockHttpServletResponse response = new MockHttpServletResponse();
        handler.onAuthenticationSuccess(new MockHttpServletRequest(), response, auth);
        return response;
    }

    private static boolean issuedSession(MockHttpServletResponse response) {
        return response.getHeaders("Set-Cookie").stream()
                .anyMatch(c -> c.startsWith("wf_refresh_") || c.startsWith("refresh_token=")
                        || c.startsWith("wf_session="));
    }

    @Test
    @DisplayName("a new person is provisioned and receives a session")
    void newPersonGetsASession() throws Exception {
        String email = address();

        MockHttpServletResponse response = signIn(email, Map.of());

        assertThat(issuedSession(response)).as("session cookies written").isTrue();
        assertThat(response.getRedirectedUrl()).doesNotContain("#error").doesNotContain("#mfa");
        assertThat(users.findByTenant_SlugAndEmailIgnoreCase("default", email)).isPresent();
    }

    @Test
    @DisplayName("a deactivated account gets no session and is not changed by the IdP")
    void deactivatedAccountIsRefused() throws Exception {
        User u = existing(address(), b -> b.active(false));

        MockHttpServletResponse response = signIn(u.getEmail(), Map.of());

        assertThat(issuedSession(response)).isFalse();
        assertThat(response.getRedirectedUrl()).endsWith("/login#error=account_unavailable");
        assertThat(users.findById(u.getId()).orElseThrow().getName()).isEqualTo("Original Name");
    }

    @Test
    @DisplayName("a locked account gets no session")
    void lockedAccountIsRefused() throws Exception {
        User u = existing(address(), b -> b.lockedUntil(LocalDateTime.now().plusMinutes(10)));

        MockHttpServletResponse response = signIn(u.getEmail(), Map.of());

        assertThat(issuedSession(response)).isFalse();
        assertThat(response.getRedirectedUrl()).endsWith("/login#error=account_unavailable");
    }

    @Test
    @DisplayName("an account with a second factor is sent to finish it, with no session yet")
    void secondFactorIsAskedFor() throws Exception {
        User u = existing(address(), b -> {});
        factors.save(MfaFactor.builder().user(u).type(MfaFactorType.TOTP)
                .label("phone").totpSecretEnc("not-used-here").verified(true).enabled(true).build());

        MockHttpServletResponse response = signIn(u.getEmail(), Map.of());

        assertThat(issuedSession(response)).isFalse();
        assertThat(response.getRedirectedUrl()).contains("/login#mfa=").contains("factors=TOTP");
    }

    @Test
    @DisplayName("group claims reach the tenant's groups")
    void groupsAreSynced() throws Exception {
        String groupName = "eng-" + UUID.randomUUID().toString().substring(0, 6);
        ScimGroup g = groups.save(ScimGroup.builder().tenant(tenant()).name(groupName).displayName(groupName).build());
        String email = address();

        signIn(email, Map.of("groups", List.of(groupName)));

        Long userId = users.findByTenant_SlugAndEmailIgnoreCase("default", email).orElseThrow().getId();
        Long members = jdbc.queryForObject(
                "select count(*) from scim_group_members where group_id = ? and user_id = ?",
                Long.class, g.getId(), userId);
        assertThat(members).as("the new account is a member of " + groupName).isEqualTo(1L);
    }
}
