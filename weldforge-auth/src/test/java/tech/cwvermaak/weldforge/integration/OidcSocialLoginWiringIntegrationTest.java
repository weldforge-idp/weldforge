package tech.cwvermaak.weldforge.integration;

import jakarta.servlet.Filter;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.oauth2.client.oidc.authentication.OidcAuthorizationCodeAuthenticationProvider;
import org.springframework.security.oauth2.client.web.OAuth2LoginAuthenticationFilter;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.util.ReflectionTestUtils;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The fault was in wiring, not in any one class: {@code oauth2Login()}
 * configured only {@code userService}, and Spring sends every sign-in whose
 * scope includes {@code openid} to the OIDC provider's own user service. Unit
 * tests of the provisioning logic all passed while it never ran for Google,
 * Microsoft, Apple or LinkedIn. This asserts the real filter chain's OIDC
 * provider holds {@code CustomOidcUserService}. Checked by class name so this
 * test also compiles -- and fails -- against code that predates that class.
 */
@SpringBootTest
@Testcontainers
@EnabledIfSystemProperty(named = "tests.integration", matches = "true")
@DisplayName("OIDC social sign-in is wired to the provisioning service")
class OidcSocialLoginWiringIntegrationTest {

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

    @Autowired FilterChainProxy filterChainProxy;

    @Test
    @DisplayName("the OIDC authorization-code provider uses CustomOidcUserService")
    void oidcProviderUsesProvisioningService() {
        OidcAuthorizationCodeAuthenticationProvider oidc = null;
        for (SecurityFilterChain chain : filterChainProxy.getFilterChains()) {
            for (Filter f : chain.getFilters()) {
                if (f instanceof OAuth2LoginAuthenticationFilter login) {
                    AuthenticationManager am = (AuthenticationManager)
                            ReflectionTestUtils.invokeMethod(login, "getAuthenticationManager");
                    for (AuthenticationProvider p : ((ProviderManager) unwrap(am)).getProviders()) {
                        if (unwrap(p) instanceof OidcAuthorizationCodeAuthenticationProvider o) oidc = o;
                    }
                }
            }
        }
        assertThat(oidc).as("an OIDC login provider is registered").isNotNull();
        Object userService = ReflectionTestUtils.getField(oidc, "userService");
        assertThat(userService.getClass().getName())
                .as("Spring's default OidcUserService skips every provisioning check")
                .isEqualTo("tech.cwvermaak.weldforge.config.CustomOidcUserService");
    }

    /** Micrometer observation wraps managers and providers in a "delegate"-holding decorator. */
    private static Object unwrap(Object o) {
        while (o != null && o.getClass().getSimpleName().startsWith("Observation")) {
            o = ReflectionTestUtils.getField(o, "delegate");
        }
        return o;
    }
}
