package tech.cwvermaak.weldforge.controller;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import tech.cwvermaak.weldforge.config.security.ContentSecurityPolicy;
import tech.cwvermaak.weldforge.config.tenant.PublicHostProperties;
import tech.cwvermaak.weldforge.model.SamlServiceProvider;
import tech.cwvermaak.weldforge.model.Tenant;
import tech.cwvermaak.weldforge.model.User;
import tech.cwvermaak.weldforge.repository.TenantRepository;
import tech.cwvermaak.weldforge.repository.UserRepository;
import tech.cwvermaak.weldforge.service.saml.SamlIdpService;
import tech.cwvermaak.weldforge.service.saml.SamlSloService;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * CONF-7.2 through the SSO endpoint itself: the HTTP-POST binding's form must
 * submit from a script carrying the same nonce the response's CSP header will
 * name. {@code ServerRenderedPagesCspTest} proves the renderer does the right
 * thing given a nonce; this proves the controller hands it the request's.
 */
class SamlIdpControllerCspTest {

    @Test
    @DisplayName("The auto-submit form's script carries the nonce the CSP header names")
    void sso_form_uses_the_request_nonce() {
        Tenant acme = Tenant.builder().id(1L).slug("acme").name("Acme").build();
        SamlServiceProvider sp = SamlServiceProvider.builder().id(10L).tenant(acme)
                .entityId("https://sp.acme.test/saml").acsUrl("https://sp.acme.test/acs")
                .nameIdFormat(SamlIdpService.NAMEID_EMAIL).enabled(true).build();
        User alice = User.builder().id(7L).tenant(acme).email("alice@acme.test").build();

        SamlIdpService idp = mock(SamlIdpService.class);
        when(idp.validateAuthnRequest(any(), eq(sp.getEntityId()))).thenReturn(sp);
        when(idp.buildSamlResponse(any(), any(), any(), any(), any(), any())).thenReturn("UkVTUE9OU0U=");
        TenantRepository tenants = mock(TenantRepository.class);
        when(tenants.findBySlug("acme")).thenReturn(Optional.of(acme));
        UserRepository users = mock(UserRepository.class);
        when(users.findByTenantIdAndEmailIgnoreCase(1L, "alice@acme.test")).thenReturn(Optional.of(alice));

        SamlIdpController controller = new SamlIdpController(idp, mock(SamlSloService.class),
                tenants, users, new PublicHostProperties());

        String authnRequest = "<samlp:AuthnRequest xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" "
                + "xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"_r1\" Version=\"2.0\">"
                + "<saml:Issuer>https://sp.acme.test/saml</saml:Issuer></samlp:AuthnRequest>";
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/t/acme/saml2/idp/sso");

        ResponseEntity<String> response = controller.ssoPost("acme",
                Base64.getEncoder().encodeToString(authnRequest.getBytes(StandardCharsets.UTF_8)),
                "relay-1",
                new UsernamePasswordAuthenticationToken("alice@acme.test", null, List.of()),
                request);

        assertThat(response.getStatusCode().value()).isEqualTo(200);
        String html = response.getBody();

        MockHttpServletResponse servletResponse = new MockHttpServletResponse();
        new ContentSecurityPolicy().writeHeaders(request, servletResponse);
        Matcher headerNonce = Pattern.compile("script-src 'self' 'nonce-([^']+)'")
                .matcher(servletResponse.getHeader(ContentSecurityPolicy.HEADER));
        assertThat(headerNonce.find()).isTrue();

        assertThat(html)
                .contains("<script nonce=\"" + headerNonce.group(1) + "\">document.forms[0].submit();</script>")
                .doesNotContain("onload")
                .contains("action=\"https://sp.acme.test/acs\"")
                .contains("name=\"RelayState\" value=\"relay-1\"");
    }
}
