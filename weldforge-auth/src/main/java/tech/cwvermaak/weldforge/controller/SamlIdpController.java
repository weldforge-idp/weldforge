package tech.cwvermaak.weldforge.controller;

import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;
import tech.cwvermaak.weldforge.model.SamlServiceProvider;
import tech.cwvermaak.weldforge.model.Tenant;
import tech.cwvermaak.weldforge.model.User;
import tech.cwvermaak.weldforge.repository.TenantRepository;
import tech.cwvermaak.weldforge.repository.UserRepository;
import tech.cwvermaak.weldforge.service.saml.SamlIdpService;
import tech.cwvermaak.weldforge.service.saml.SamlInboundMessageParser;
import tech.cwvermaak.weldforge.service.saml.SamlMessageException;
import tech.cwvermaak.weldforge.service.saml.SamlSloService;

/**
 * SAML 2.0 Identity Provider endpoints. Issues signed SAML assertions
 * to registered downstream Service Providers.
 *
 * Metadata is public; SSO endpoints require authentication (the user
 * must be logged in before an assertion can be issued).
 */
@RestController
@RequiredArgsConstructor
@Slf4j
public class SamlIdpController {

    private final SamlIdpService samlIdpService;
    private final SamlSloService samlSloService;
    private final TenantRepository tenantRepository;
    private final UserRepository userRepository;

    /**
     * IdP metadata — public endpoint, same pattern as OIDC discovery.
     */
    @GetMapping(value = "/t/{slug}/saml2/idp/metadata",
                produces = "application/samlmetadata+xml")
    public ResponseEntity<String> metadata(@PathVariable String slug, HttpServletRequest request) {
        Tenant tenant = requireTenant(slug);
        String baseUrl = baseUrl(request);
        return ResponseEntity.ok(samlIdpService.generateMetadata(tenant, baseUrl));
    }

    /**
     * SP-initiated SSO via HTTP-POST binding. The SP sends a SAMLRequest
     * form parameter. If the user is authenticated, a signed SAML Response
     * is returned via an auto-submitting form; otherwise the caller gets 401.
     */
    @PostMapping(value = "/t/{slug}/saml2/idp/sso",
                 produces = MediaType.TEXT_HTML_VALUE)
    public ResponseEntity<String> ssoPost(@PathVariable String slug,
                                           @RequestParam("SAMLRequest") String samlRequest,
                                           @RequestParam(value = "RelayState", required = false) String relayState,
                                           Authentication authentication,
                                           HttpServletRequest request) {
        return handleSso(slug, samlRequest, relayState, authentication);
    }

    /**
     * SP-initiated SSO via HTTP-Redirect binding.
     */
    @GetMapping(value = "/t/{slug}/saml2/idp/sso",
                produces = MediaType.TEXT_HTML_VALUE)
    public ResponseEntity<String> ssoRedirect(@PathVariable String slug,
                                               @RequestParam("SAMLRequest") String samlRequest,
                                               @RequestParam(value = "RelayState", required = false) String relayState,
                                               Authentication authentication) {
        return handleSso(slug, samlRequest, relayState, authentication);
    }

    /**
     * IdP-initiated Single Logout (PRD SAM-06). Builds LogoutRequests for
     * every SP with a configured SLO URL and returns a JSON response
     * listing each SP and its encoded LogoutRequest payload. The binding
     * query parameter selects POST (default) or REDIRECT encoding.
     */
    @PostMapping(value = "/t/{slug}/saml2/idp/slo",
                 produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> singleLogout(@PathVariable String slug,
                                          @RequestParam(value = "binding", defaultValue = "POST") String bindingParam,
                                          Authentication authentication) {
        if (authentication == null || !authentication.isAuthenticated()
                || !(authentication.getPrincipal() instanceof String email)) {
            return ResponseEntity.status(401).body(java.util.Map.of("error", "Authentication required"));
        }

        Tenant tenant = requireTenant(slug);
        User user = userRepository.findByTenantIdAndEmailIgnoreCase(tenant.getId(), email)
                .orElse(null);
        if (user == null) {
            return ResponseEntity.status(403).body(java.util.Map.of("error", "User not found in tenant"));
        }

        SamlSloService.Binding binding = "REDIRECT".equalsIgnoreCase(bindingParam)
                ? SamlSloService.Binding.REDIRECT
                : SamlSloService.Binding.POST;
        java.util.List<SamlSloService.SloPayload> payloads = samlSloService.initiateLogout(tenant, user, binding);

        java.util.List<java.util.Map<String, Object>> spList = payloads.stream()
                .map(p -> {
                    java.util.Map<String, Object> entry = new java.util.LinkedHashMap<>();
                    entry.put("spId", p.spId());
                    entry.put("entityId", p.entityId());
                    entry.put("spName", p.spName());
                    entry.put("sloUrl", p.sloUrl());
                    entry.put("logoutRequest", p.logoutRequest());
                    entry.put("binding", p.binding().name());
                    return entry;
                })
                .toList();

        return ResponseEntity.ok(java.util.Map.of(
                "status", "logout_initiated",
                "spCount", payloads.size(),
                "binding", binding.name(),
                "serviceProviders", spList));
    }

    /**
     * SP-initiated Single Logout (PRD SAM-06). Receives a SAML
     * LogoutRequest from an SP and returns an encoded LogoutResponse.
     * The caller picks POST or REDIRECT binding via query param.
     */
    @PostMapping(value = "/t/{slug}/saml2/sp-slo",
                 produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> spInitiatedLogout(@PathVariable String slug,
                                                @RequestParam("SAMLRequest") String samlRequest,
                                                @RequestParam(value = "binding", defaultValue = "POST") String bindingParam) {
        Tenant tenant = requireTenant(slug);

        String xml;
        try {
            byte[] decoded = java.util.Base64.getDecoder().decode(samlRequest);
            xml = new String(decoded, java.nio.charset.StandardCharsets.UTF_8);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(java.util.Map.of("error", "Invalid SAMLRequest: " + e.getMessage()));
        }

        String issuer;
        String inResponseTo;
        try {
            SamlInboundMessageParser.ParsedMessage parsed = SamlInboundMessageParser.parse(xml);
            issuer = parsed.issuer();
            inResponseTo = parsed.messageId();
        } catch (SamlMessageException e) {
            return ResponseEntity.badRequest().body(java.util.Map.of("error", "Invalid SAMLRequest: " + e.getMessage()));
        }
        if (issuer == null) {
            return ResponseEntity.badRequest().body(java.util.Map.of("error", "Missing Issuer in LogoutRequest"));
        }

        SamlServiceProvider sp = samlIdpService.validateAuthnRequest(tenant, issuer);

        // Verify the LogoutRequest signature when this SP requires signing.
        try {
            samlIdpService.verifyAuthnRequestSignature(sp, xml);
        } catch (SamlMessageException e) {
            return ResponseEntity.badRequest().body(
                    java.util.Map.of("error", "LogoutRequest signature rejected: " + e.getMessage()));
        }

        SamlSloService.Binding binding = "REDIRECT".equalsIgnoreCase(bindingParam)
                ? SamlSloService.Binding.REDIRECT
                : SamlSloService.Binding.POST;
        String response = samlSloService.buildLogoutResponse(tenant, sp, inResponseTo, binding);

        return ResponseEntity.ok(java.util.Map.of(
                "status", "logged_out",
                "spEntityId", sp.getEntityId(),
                "binding", binding.name(),
                "logoutResponse", response,
                "destination", sp.getSloUrl()));
    }

    private ResponseEntity<String> handleSso(String slug, String samlRequest, String relayState,
                                              Authentication authentication) {
        if (authentication == null || !authentication.isAuthenticated()
                || !(authentication.getPrincipal() instanceof String email)) {
            return ResponseEntity.status(401).body("Authentication required");
        }

        Tenant tenant = requireTenant(slug);

        // Decode the AuthnRequest to extract the issuer (SP entity ID)
        String issuer;
        String inResponseTo = null;
        String xml;
        try {
            byte[] decoded = java.util.Base64.getDecoder().decode(samlRequest);
            // For redirect binding, the request may be deflated
            try {
                java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();
                java.util.zip.InflaterOutputStream inflater = new java.util.zip.InflaterOutputStream(baos);
                inflater.write(decoded);
                inflater.close();
                xml = baos.toString(java.nio.charset.StandardCharsets.UTF_8);
            } catch (Exception e) {
                // Not compressed — raw base64
                xml = new String(decoded, java.nio.charset.StandardCharsets.UTF_8);
            }

            // XXE-hardened, namespace-aware DOM parse (B-SAML-1).
            SamlInboundMessageParser.ParsedMessage parsed = SamlInboundMessageParser.parse(xml);
            issuer = parsed.issuer();
            inResponseTo = parsed.messageId();
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Invalid SAMLRequest: " + e.getMessage());
        }
        if (issuer == null) {
            return ResponseEntity.badRequest().body("Missing Issuer in AuthnRequest");
        }

        SamlServiceProvider sp = samlIdpService.validateAuthnRequest(tenant, issuer);

        // Verify the request signature when this SP is configured to sign its
        // AuthnRequests (B-SAML-1 part a). No-op for SPs that don't sign.
        try {
            samlIdpService.verifyAuthnRequestSignature(sp, xml);
        } catch (SamlMessageException e) {
            return ResponseEntity.status(400).body("AuthnRequest signature rejected: " + e.getMessage());
        }

        User user = userRepository.findByTenantIdAndEmailIgnoreCase(tenant.getId(), email)
                .orElse(null);
        if (user == null) {
            return ResponseEntity.status(403).body("User not found in tenant");
        }

        String samlResponse = samlIdpService.buildSamlResponse(tenant, user, sp, inResponseTo);

        // Build auto-submit form (POST binding to SP's ACS URL)
        String html = buildAutoSubmitForm(sp.getAcsUrl(), samlResponse, relayState);
        return ResponseEntity.ok(html);
    }

    private static String buildAutoSubmitForm(String acsUrl, String samlResponse, String relayState) {
        StringBuilder html = new StringBuilder();
        html.append("<!DOCTYPE html><html><body onload=\"document.forms[0].submit()\">");
        html.append("<form method=\"POST\" action=\"").append(escapeHtml(acsUrl)).append("\">");
        html.append("<input type=\"hidden\" name=\"SAMLResponse\" value=\"")
                .append(samlResponse).append("\"/>");
        if (relayState != null && !relayState.isBlank()) {
            html.append("<input type=\"hidden\" name=\"RelayState\" value=\"")
                    .append(escapeHtml(relayState)).append("\"/>");
        }
        html.append("<noscript><input type=\"submit\" value=\"Continue\"/></noscript>");
        html.append("</form></body></html>");
        return html.toString();
    }

    private Tenant requireTenant(String slug) {
        return tenantRepository.findBySlug(slug)
                .orElseThrow(() -> new jakarta.persistence.EntityNotFoundException("Tenant not found: " + slug));
    }

    private static String baseUrl(HttpServletRequest request) {
        String scheme = request.getScheme();
        String host = request.getServerName();
        int port = request.getServerPort();
        String forwarded = request.getHeader("X-Forwarded-Proto");
        if (forwarded != null) scheme = forwarded;
        if (("http".equals(scheme) && port == 80) || ("https".equals(scheme) && port == 443)) {
            return scheme + "://" + host;
        }
        return scheme + "://" + host + ":" + port;
    }

    private static String escapeHtml(String s) {
        if (s == null) return "";
        return s.replace("&", "&amp;").replace("<", "&lt;")
                .replace(">", "&gt;").replace("\"", "&quot;");
    }
}
