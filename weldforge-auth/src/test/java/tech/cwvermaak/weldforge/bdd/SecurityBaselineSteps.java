package tech.cwvermaak.weldforge.bdd;

import io.cucumber.java.After;
import io.cucumber.java.en.Then;
import io.cucumber.java.en.When;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import tech.cwvermaak.weldforge.config.AuthJsonContentTypeFilter;
import tech.cwvermaak.weldforge.config.GlobalExceptionHandler;
import tech.cwvermaak.weldforge.config.scim.ScimAuthenticationFilter;
import tech.cwvermaak.weldforge.config.security.ContentSecurityPolicy;
import tech.cwvermaak.weldforge.config.tenant.PublicHostProperties;
import tech.cwvermaak.weldforge.controller.CspPageFixtures;
import tech.cwvermaak.weldforge.model.Tenant;
import tech.cwvermaak.weldforge.repository.AppClientRepository;
import tech.cwvermaak.weldforge.repository.TenantRepository;
import tech.cwvermaak.weldforge.service.oidc.OidcAuthorizationException;
import tech.cwvermaak.weldforge.service.oidc.OidcAuthorizationService;

import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

/**
 * Steps for {@code security_baseline.feature} (CONF-7.2, CONF-7.3).
 */
public class SecurityBaselineSteps {

    /**
     * JSON ahead of XML, as Spring Boot orders its converters. Standalone MockMvc
     * uses raw Spring MVC's order, which puts XML first whenever
     * jackson-dataformat-xml is on the classpath (it is), and would answer a
     * request without an Accept header in XML -- something the real service
     * never does. The full-chain integration test runs Boot's real ordering.
     */
    private static final org.springframework.http.converter.HttpMessageConverter<?>[] JSON_FIRST = {
            new org.springframework.http.converter.StringHttpMessageConverter(),
            new org.springframework.http.converter.json.MappingJackson2HttpMessageConverter()
    };

    private MockHttpServletRequest request;
    private MockHttpServletResponse response;
    private String headerNonce;
    private String page;
    private String body;
    private String contentType;

    @After
    public void clearRequestContext() {
        RequestContextHolder.resetRequestAttributes();
    }

    private static String nonceIn(String csp) {
        Matcher m = Pattern.compile("script-src 'self' 'nonce-([^']+)'").matcher(csp);
        assertThat(m.find()).as("script-src carries a nonce: %s", csp).isTrue();
        return m.group(1);
    }

    private String writeHeaders(MockHttpServletRequest req) {
        MockHttpServletResponse res = new MockHttpServletResponse();
        new ContentSecurityPolicy().writeHeaders(req, res);
        return res.getHeader(ContentSecurityPolicy.HEADER);
    }

    // ---- CONF-7.2 -----------------------------------------------------

    @When("any response is returned")
    public void anyResponse() {
        request = new MockHttpServletRequest("GET", "/api/auth/tenants/acme/branding");
        response = new MockHttpServletResponse();
        new ContentSecurityPolicy().writeHeaders(request, response);
    }

    @Then("Content-Security-Policy is present with default-src 'self'")
    public void cspPresent() {
        assertThat(response.getHeader(ContentSecurityPolicy.HEADER)).startsWith("default-src 'self'");
    }

    @Then("inline scripts and styles need this response's nonce")
    public void inlineNeedsNonce() {
        String csp = response.getHeader(ContentSecurityPolicy.HEADER);
        String nonce = ContentSecurityPolicy.nonce(request);
        assertThat(csp)
                .contains("script-src 'self' 'nonce-" + nonce + "'")
                .contains("style-src 'self' 'nonce-" + nonce + "'")
                .doesNotContain("unsafe-inline");
    }

    @Then("no page may frame the response")
    public void noFraming() {
        assertThat(response.getHeader(ContentSecurityPolicy.HEADER)).contains("frame-ancestors 'none'");
    }

    @Then("no two responses share a nonce")
    public void noncesDiffer() {
        assertThat(nonceIn(writeHeaders(new MockHttpServletRequest())))
                .isNotEqualTo(nonceIn(writeHeaders(new MockHttpServletRequest())));
    }

    @When("^the (consent screen|SAML POST form|tenant verification page|hosted sign-in page) is served$")
    public void servePage(String name) {
        request = new MockHttpServletRequest("GET", "/page");
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));
        String nonce = ContentSecurityPolicy.nonce(request);
        page = switch (name) {
            case "consent screen" -> CspPageFixtures.consentPage(nonce);
            case "SAML POST form" -> CspPageFixtures.samlPostForm(nonce);
            case "tenant verification page" -> CspPageFixtures.verifyContactPage(nonce);
            case "hosted sign-in page" -> CspPageFixtures.hostedSignInPage();
            default -> throw new IllegalArgumentException("unknown page: " + name);
        };
        headerNonce = nonceIn(writeHeaders(request));
    }

    @Then("its inline blocks carry a per-render nonce matching the CSP")
    public void blocksCarryNonce() {
        Matcher blocks = Pattern.compile("<(style|script)([^>]*)>").matcher(page);
        int seen = 0;
        while (blocks.find()) {
            seen++;
            assertThat(blocks.group(2)).as("<%s>", blocks.group(1))
                    .contains("nonce=\"" + headerNonce + "\"");
        }
        assertThat(seen).isPositive();
    }

    @Then("the page needs nothing the policy forbids")
    public void nothingForbidden() {
        // Neither can carry a nonce, so the policy blocks them outright.
        assertThat(page).doesNotContainPattern("\\son[a-z]+\\s*=");
        assertThat(page).doesNotContainPattern("\\sstyle\\s*=");
        assertThat(page).doesNotContainPattern("<(script|link)[^>]+(src|href)=['\"]http://");
    }

    // ---- CONF-7.3 -----------------------------------------------------

    @When("an \\/api\\/** call fails validation")
    public void apiValidationFails() throws Exception {
        MvcResult result = MockMvcBuilders.standaloneSetup(new testfixtures.web.ValidatingController())
                .setControllerAdvice(new GlobalExceptionHandler())
                .setMessageConverters(JSON_FIRST)
                .build()
                // The required "email" parameter is missing.
                .perform(post("/api/fixture/users"))
                .andReturn();
        assertThat(result.getResponse().getStatus()).isEqualTo(400);
        body = result.getResponse().getContentAsString();
        contentType = result.getResponse().getContentType();
    }

    @When("an \\/api\\/** call is refused for its content type")
    public void apiRefusedForContentType() throws Exception {
        MockHttpServletRequest req = new MockHttpServletRequest("POST", "/api/auth/login");
        req.setContentType("text/plain");
        req.setContent("identifier=u".getBytes());
        MockHttpServletResponse res = new MockHttpServletResponse();
        new AuthJsonContentTypeFilter().doFilter(req, res, (rq, rs) -> {
            throw new AssertionError("the chain must not continue");
        });
        assertThat(res.getStatus()).isEqualTo(415);
        body = res.getContentAsString();
        contentType = res.getContentType();
    }

    @Then("the content type is application\\/problem+json")
    public void problemContentType() {
        assertThat(contentType).startsWith("application/problem+json");
    }

    @Then("the body carries type, title, status and detail")
    public void problemMembers() {
        assertThat(body)
                .containsPattern("\"type\":\"tag:weldforge\\.org,2026:problem:[a-z_]+\"")
                .contains("\"title\":")
                .containsPattern("\"status\":4\\d\\d")
                .contains("\"detail\":");
    }

    @Then("the body still carries the legacy error and message members")
    public void legacyMembers() {
        assertThat(body).contains("\"error\":\"missing_parameter\"").contains("\"message\":");
    }

    @When("an OAuth2 token request fails")
    public void oauthTokenFails() throws Exception {
        TenantRepository tenants = mock(TenantRepository.class);
        when(tenants.findBySlug("acme"))
                .thenReturn(Optional.of(Tenant.builder().id(1L).slug("acme").name("Acme").build()));
        OidcAuthorizationService authz = mock(OidcAuthorizationService.class);
        when(authz.exchangeCode(any(), any()))
                .thenThrow(new OidcAuthorizationException("invalid_grant", "Authorization code has expired"));

        // The global advice is registered too: the controller's own handler
        // must still win, or OAuth clients would be handed a problem document.
        MvcResult result = MockMvcBuilders.standaloneSetup(new tech.cwvermaak.weldforge.controller
                        .OidcAuthorizationController(tenants, null, null, authz, null,
                        new PublicHostProperties(), null, null, null, null))
                .setControllerAdvice(new GlobalExceptionHandler())
                .setMessageConverters(JSON_FIRST)
                .build()
                .perform(post("/t/acme/oauth2/token")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .content("grant_type=authorization_code&code=x&client_id=c&client_secret=s"))
                .andReturn();
        body = result.getResponse().getContentAsString();
        contentType = result.getResponse().getContentType();
    }

    @Then("the body is still \\{error, error_description\\}")
    public void oauthShape() {
        assertThat(contentType).doesNotContain("problem");
        assertThat(body)
                .isEqualTo("{\"error\":\"invalid_grant\",\"error_description\":\"Authorization code has expired\"}");
    }

    @When("a SCIM request fails")
    public void scimFails() throws Exception {
        MockHttpServletRequest req = new MockHttpServletRequest("GET", "/scim/v2/acme/Users");
        MockHttpServletResponse res = new MockHttpServletResponse();
        new ScimAuthenticationFilter(mock(AppClientRepository.class)).doFilter(req, res, (rq, rs) -> {
            throw new AssertionError("the chain must not continue");
        });
        assertThat(res.getStatus()).isEqualTo(401);
        body = res.getContentAsString();
        contentType = res.getContentType();
    }

    @Then("the body is still a SCIM error response")
    public void scimShape() {
        assertThat(contentType).startsWith("application/scim+json");
        assertThat(body)
                .contains("\"schemas\":[\"urn:ietf:params:scim:api:messages:2.0:Error\"]")
                .doesNotContain("\"type\":\"tag:");
    }
}
