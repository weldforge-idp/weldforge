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
    private final tech.cwvermaak.weldforge.config.tenant.PublicHostProperties publicHost;

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
        return handleSso(slug, samlRequest, relayState, authentication, request);
    }

    /**
     * SP-initiated SSO via HTTP-Redirect binding.
     */
    @GetMapping(value = "/t/{slug}/saml2/idp/sso",
                produces = MediaType.TEXT_HTML_VALUE)
    public ResponseEntity<String> ssoRedirect(@PathVariable String slug,
                                               @RequestParam("SAMLRequest") String samlRequest,
                                               @RequestParam(value = "RelayState", required = false) String relayState,
                                               Authentication authentication,
                                               HttpServletRequest request) {
        return handleSso(slug, samlRequest, relayState, authentication, request);
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
                                          Authentication authentication,
                                          HttpServletRequest request) {
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
        // Each LogoutRequest names this session (CONF-5.2), so an SP ends the
        // session it holds for this login rather than all of them.
        java.util.List<SamlSloService.SloPayload> payloads =
                samlSloService.initiateLogout(tenant, user, binding, sessionId(request));

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
     * LogoutRequest from an SP, ends the sessions it names (CONF-5.2), and
     * returns an encoded LogoutResponse. The caller picks POST or REDIRECT
     * binding via query param.
     *
     * <p>Authenticated like the rest of {@code /t/**}: the request must arrive
     * with the user's own session, and its NameID must be that user. A logout
     * can therefore only ever end the caller's own sessions.
     */
    @PostMapping(value = "/t/{slug}/saml2/sp-slo",
                 produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> spInitiatedLogout(@PathVariable String slug,
                                                @RequestParam("SAMLRequest") String samlRequest,
                                                @RequestParam(value = "binding", defaultValue = "POST") String bindingParam,
                                                Authentication authentication,
                                                HttpServletRequest request,
                                                jakarta.servlet.http.HttpServletResponse servletResponse) {
        if (authentication == null || !authentication.isAuthenticated()
                || !(authentication.getPrincipal() instanceof String email)) {
            return ResponseEntity.status(401).body(java.util.Map.of("error", "Authentication required"));
        }
        Tenant tenant = requireTenant(slug);

        String xml;
        try {
            byte[] decoded = java.util.Base64.getDecoder().decode(samlRequest);
            xml = new String(decoded, java.nio.charset.StandardCharsets.UTF_8);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(java.util.Map.of("error", "Invalid SAMLRequest: " + e.getMessage()));
        }

        SamlInboundMessageParser.ParsedMessage parsed;
        try {
            parsed = SamlInboundMessageParser.parse(xml);
        } catch (SamlMessageException e) {
            return ResponseEntity.badRequest().body(java.util.Map.of("error", "Invalid SAMLRequest: " + e.getMessage()));
        }
        if (parsed.issuer() == null) {
            return ResponseEntity.badRequest().body(java.util.Map.of("error", "Missing Issuer in LogoutRequest"));
        }

        SamlServiceProvider sp = samlIdpService.validateAuthnRequest(tenant, parsed.issuer());

        // Verify the LogoutRequest signature when this SP requires signing.
        try {
            samlIdpService.verifyAuthnRequestSignature(sp, xml);
        } catch (SamlMessageException e) {
            return ResponseEntity.badRequest().body(
                    java.util.Map.of("error", "LogoutRequest signature rejected: " + e.getMessage()));
        }

        User user = userRepository.findByTenantIdAndEmailIgnoreCase(tenant.getId(), email).orElse(null);
        if (user == null) {
            return ResponseEntity.status(403).body(java.util.Map.of("error", "User not found in tenant"));
        }

        SamlSloService.Binding binding = "REDIRECT".equalsIgnoreCase(bindingParam)
                ? SamlSloService.Binding.REDIRECT
                : SamlSloService.Binding.POST;

        // A LogoutRequest about someone else is answered, truthfully, with a
        // Requester error and ends nothing. Transient NameIDs are random per
        // assertion and cannot be compared; the SessionIndex match below is
        // confined to this user's sessions, so nothing is lost by skipping it.
        if (!nameIdMatches(parsed.nameId(), user, sp)) {
            log.warn("SP-initiated logout refused: NameID does not match the caller sp={} tenant={}",
                    sp.getEntityId(), tenant.getSlug());
            return ResponseEntity.ok(java.util.Map.of(
                    "status", "not_logged_out",
                    "spEntityId", sp.getEntityId(),
                    "binding", binding.name(),
                    "logoutResponse", samlSloService.buildLogoutResponse(tenant, sp, parsed.messageId(),
                            binding, SamlSloService.STATUS_REQUESTER),
                    "destination", sp.getSloUrl()));
        }

        SamlSloService.LogoutOutcome outcome = samlSloService.terminateSessions(
                tenant, sp, user, parsed.sessionIndexes(), sessionId(request));
        if (outcome.currentSessionEnded()) {
            // The browser presenting this request is signed out too; without
            // clearing the cookie it would keep offering a dead session.
            clearSessionCookies(servletResponse, tenant.getSlug());
        }

        String response = samlSloService.buildLogoutResponse(tenant, sp, parsed.messageId(), binding);
        return ResponseEntity.ok(java.util.Map.of(
                "status", "logged_out",
                "spEntityId", sp.getEntityId(),
                "binding", binding.name(),
                "sessionsEnded", outcome.allSessions() ? "all" : String.valueOf(outcome.sessionsEnded()),
                "logoutResponse", response,
                "destination", sp.getSloUrl()));
    }

    private static boolean nameIdMatches(String nameId, User user, SamlServiceProvider sp) {
        String format = sp.getNameIdFormat();
        if (format != null && format.contains("transient")) return true;
        return nameId != null && nameId.equalsIgnoreCase(SamlIdpService.resolveNameId(user, format));
    }

    /** The login session the caller's token belongs to (CONF-5.2), or null. */
    private static String sessionId(HttpServletRequest request) {
        Object sid = request.getAttribute(
                tech.cwvermaak.weldforge.config.JwtAuthenticationFilter.SESSION_ID_ATTRIBUTE);
        return sid == null ? null : sid.toString();
    }

    // Written with the same Domain and flags the login set, or the browser
    // treats the deletion as a different cookie and keeps the original.
    private void clearSessionCookies(jakarta.servlet.http.HttpServletResponse response, String tenantSlug) {
        clearCookie(response, tech.cwvermaak.weldforge.config.JwtAuthenticationFilter.SESSION_COOKIE, "/");
        clearCookie(response, tech.cwvermaak.weldforge.service.AuthService.REFRESH_COOKIE, "/api/auth");
        // B-TEN-7: this tenant's own refresh cookie; other tenants' stay.
        clearCookie(response, tech.cwvermaak.weldforge.service.AuthService.refreshCookieName(tenantSlug), "/api/auth");
    }

    private void clearCookie(jakarta.servlet.http.HttpServletResponse response, String name, String path) {
        jakarta.servlet.http.Cookie cookie = new jakarta.servlet.http.Cookie(name, "");
        cookie.setPath(path);
        cookie.setHttpOnly(true);
        cookie.setSecure(publicHost.isSecureCookies());
        String domain = publicHost.cookieDomain();
        if (domain != null) cookie.setDomain(domain);
        cookie.setMaxAge(0);
        response.addCookie(cookie);
    }

    private ResponseEntity<String> handleSso(String slug, String samlRequest, String relayState,
                                              Authentication authentication,
                                              HttpServletRequest request) {
        if (authentication == null || !authentication.isAuthenticated()
                || !(authentication.getPrincipal() instanceof String email)) {
            return ResponseEntity.status(401).body("Authentication required");
        }

        Tenant tenant = requireTenant(slug);

        // Decode the AuthnRequest to extract the issuer (SP entity ID)
        String issuer;
        String inResponseTo = null;
        java.time.Instant issueInstant = null;
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
            issueInstant = parsed.issueInstant();
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

        // CONF-5.3: fresh, single-use requests. Deliberately AFTER the
        // signature check -- recording an unverified request ID would let
        // anyone burn an arbitrary id and lock the real request out of its own
        // login.
        try {
            samlIdpService.rejectReplayedRequest(tenant, sp, inResponseTo, issueInstant);
        } catch (SamlMessageException e) {
            return ResponseEntity.status(400).body("AuthnRequest rejected: " + e.getMessage());
        }

        User user = userRepository.findByTenantIdAndEmailIgnoreCase(tenant.getId(), email)
                .orElse(null);
        if (user == null) {
            return ResponseEntity.status(403).body("User not found in tenant");
        }

        // CONF-5.1: the session's own authentication methods, read from the
        // request attribute the JWT filter sets -- never from a parameter,
        // which the caller controls. Without this the assertion would keep
        // reporting a password regardless of what the user actually used.
        java.util.List<String> sessionAmr = java.util.List.of();
        Object amrAttribute = request.getAttribute(
                tech.cwvermaak.weldforge.config.JwtAuthenticationFilter.AMR_ATTRIBUTE);
        if (amrAttribute instanceof java.util.List<?> methods) {
            sessionAmr = methods.stream().map(String::valueOf).toList();
        }

        // CONF-5.2: the SessionIndex is derived from the login session, so it
        // is the same on every assertion this session receives and an SP can
        // name it at logout. A token minted before sessions were named has no
        // sid; it gets a one-off index, which is what every assertion had
        // before, and cannot be targeted -- a logout then ends all sessions.
        String sid = sessionId(request);
        String sessionIndex = sid == null ? null : SamlIdpService.sessionIndexFor(sid, sp);

        String samlResponse = samlIdpService.buildSamlResponse(
                tenant, user, sp, inResponseTo, sessionAmr, sessionIndex);

        // Build auto-submit form (POST binding to SP's ACS URL)
        String html = buildAutoSubmitForm(sp.getAcsUrl(), samlResponse, relayState,
                tech.cwvermaak.weldforge.config.security.ContentSecurityPolicy.nonce(request));
        return ResponseEntity.ok(html);
    }

    /**
     * The HTTP-POST binding's self-submitting form. The submit runs from a
     * nonce-carrying script rather than {@code <body onload>}: the CSP
     * (CONF-7.2) forbids inline event handlers outright, and a nonce cannot
     * be attached to one. {@code <noscript>} keeps a manual button.
     */
    static String buildAutoSubmitForm(String acsUrl, String samlResponse, String relayState,
                                      String cspNonce) {
        StringBuilder html = new StringBuilder();
        html.append("<!DOCTYPE html><html><body>");
        html.append("<form method=\"POST\" action=\"").append(escapeHtml(acsUrl)).append("\">");
        html.append("<input type=\"hidden\" name=\"SAMLResponse\" value=\"")
                .append(samlResponse).append("\"/>");
        if (relayState != null && !relayState.isBlank()) {
            html.append("<input type=\"hidden\" name=\"RelayState\" value=\"")
                    .append(escapeHtml(relayState)).append("\"/>");
        }
        html.append("<noscript><input type=\"submit\" value=\"Continue\"/></noscript>");
        html.append("</form>");
        html.append("<script nonce=\"").append(escapeHtml(cspNonce)).append("\">")
            .append("document.forms[0].submit();</script>");
        html.append("</body></html>");
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
