package tech.cwvermaak.weldforge.controller;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import tech.cwvermaak.weldforge.model.Tenant;
import tech.cwvermaak.weldforge.repository.TenantRepository;
import tech.cwvermaak.weldforge.service.oidc.TenantSigningKeyService;

import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * CONF-4.2 — the discovery document must describe what the server does.
 *
 * <p>It advertised neither the {@code refresh_token} grant nor the registration
 * endpoint, both of which are implemented and reachable, so a client doing
 * capability detection — the entire purpose of discovery — concluded neither
 * existed.
 *
 * <p>The last test is the one that matters most long-term: it walks every URL
 * the document advertises and asserts a controller actually maps it. That is
 * what stops the document drifting away from the server again, which is how it
 * got into this state.
 */
class OidcDiscoveryCompletenessTest {

    private OidcDiscoveryController controller;

    @BeforeEach
    void setUp() {
        Tenant leap = new Tenant();
        leap.setId(1L);
        leap.setSlug("leap");

        TenantRepository tenantRepository = mock(TenantRepository.class);
        when(tenantRepository.findBySlug("leap")).thenReturn(Optional.of(leap));

        controller = new OidcDiscoveryController(tenantRepository, mock(TenantSigningKeyService.class));
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> discovery() {
        MockHttpServletRequest request = new MockHttpServletRequest(
                "GET", "/t/leap/.well-known/openid-configuration");
        request.setScheme("https");
        request.setServerName("sso.weldforge.org");
        request.setServerPort(443);
        return controller.discovery("leap", request).getBody();
    }

    @Test
    @DisplayName("The refresh_token grant is advertised, because it is implemented")
    void refresh_token_grant_is_advertised() {
        assertThat((List<String>) discovery().get("grant_types_supported"))
                .contains("authorization_code", "refresh_token", "client_credentials");
    }

    @Test
    @DisplayName("The registration endpoint is advertised, because it is live")
    void registration_endpoint_is_advertised() {
        assertThat(discovery().get("registration_endpoint"))
                .isEqualTo("https://sso.weldforge.org/t/leap/oauth2/register");
    }

    @Test
    @DisplayName("client_secret_basic is advertised now that it works")
    void basic_auth_is_advertised() {
        assertThat((List<String>) discovery().get("token_endpoint_auth_methods_supported"))
                .containsExactly("client_secret_basic", "client_secret_post", "none");
    }

    @Test
    @DisplayName("RFC 9207 issuer identification is advertised")
    void iss_parameter_is_advertised() {
        // Advertised so a client knows it can rely on the parameter -- which is
        // what lets it treat a response WITHOUT one as suspicious.
        assertThat(discovery().get("authorization_response_iss_parameter_supported"))
                .isEqualTo(true);
    }

    @Test
    @DisplayName("Advertised claims include the ones actually minted")
    void claims_match_what_is_minted() {
        assertThat((List<String>) discovery().get("claims_supported"))
                .contains("amr", "roles", "picture", "auth_time");
    }

    @Test
    @DisplayName("OIDC Discovery's required metadata is all present")
    void required_metadata_present() {
        assertThat(discovery()).containsKeys(
                "issuer", "authorization_endpoint", "token_endpoint", "jwks_uri",
                "response_types_supported", "subject_types_supported",
                "id_token_signing_alg_values_supported");
    }

    @Test
    @DisplayName("Every advertised endpoint is mapped by a controller")
    void every_advertised_endpoint_is_routable() {
        Map<String, Object> doc = discovery();
        String issuer = (String) doc.get("issuer");

        List<String> advertised = new ArrayList<>();
        doc.forEach((key, value) -> {
            if (key.endsWith("_endpoint") || key.equals("jwks_uri")) {
                advertised.add(((String) value).substring(issuer.length() - "/t/leap".length()));
            }
        });
        assertThat(advertised).isNotEmpty();

        // Collect every path this application maps, from the annotations
        // themselves, so the assertion tracks the controllers rather than a
        // hand-maintained list that would drift the same way the document did.
        List<String> mapped = new ArrayList<>();
        for (Class<?> type : List.of(OidcDiscoveryController.class, OidcAuthorizationController.class,
                                     OidcUserinfoController.class, OidcIntrospectRevokeController.class,
                                     OidcLogoutController.class, OidcRegistrationController.class)) {
            for (Method m : type.getDeclaredMethods()) {
                for (var annotation : m.getAnnotations()) {
                    String name = annotation.annotationType().getSimpleName();
                    if (!name.endsWith("Mapping")) continue;
                    try {
                        Method valueAccessor = annotation.annotationType().getMethod("value");
                        for (String path : (String[]) valueAccessor.invoke(annotation)) {
                            mapped.add(path);
                        }
                    } catch (ReflectiveOperationException ignored) {
                        // Not a path-bearing mapping annotation.
                    }
                }
            }
        }

        for (String path : advertised) {
            String templated = path.replace("/t/leap/", "/t/{slug}/");
            assertThat(mapped)
                    .as("discovery advertises %s but no controller maps it", path)
                    .anySatisfy(m -> assertThat(normalise(m)).isEqualTo(normalise(templated)));
        }
    }

    /** Path variables are named differently across controllers; only the shape matters. */
    private static String normalise(String path) {
        return path.replaceAll("\\{[^}]+}", "{}");
    }
}
