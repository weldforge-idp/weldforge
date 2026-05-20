package tech.cwvermaak.weldforge.controller;

import jakarta.persistence.EntityNotFoundException;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;
import tech.cwvermaak.weldforge.config.tenant.PublicHostProperties;
import tech.cwvermaak.weldforge.model.OidcClient;
import tech.cwvermaak.weldforge.model.Tenant;
import tech.cwvermaak.weldforge.model.User;
import tech.cwvermaak.weldforge.repository.OidcClientRepository;
import tech.cwvermaak.weldforge.repository.TenantRepository;
import tech.cwvermaak.weldforge.repository.UserRepository;
import tech.cwvermaak.weldforge.service.oidc.OidcAuthorizationException;
import tech.cwvermaak.weldforge.service.oidc.OidcAuthorizationService;
import tech.cwvermaak.weldforge.service.oidc.OidcAuthorizationService.AuthorizeRequest;
import tech.cwvermaak.weldforge.service.oidc.OidcAuthorizationService.CodeExchangeRequest;
import tech.cwvermaak.weldforge.service.oidc.OidcAuthorizationService.CodeExchangeResult;
import tech.cwvermaak.weldforge.service.oidc.OidcTokenService;
import tech.cwvermaak.weldforge.service.oidc.OidcTokenService.IssuedTokens;

import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The {@code /authorize} and {@code /token} endpoints. The /authorize
 * endpoint runs a small state machine:
 *
 *   1. unauthenticated → 302 to the SPA login page with a return URL
 *   2. authenticated, no consent yet → server-rendered consent screen
 *   3. consent allowed → mint code, 302 to redirect_uri
 *   4. consent denied  → 302 to redirect_uri with error=access_denied
 *
 * Step 3 lives in {@link #decide}, which validates that the consent
 * form's hidden fields haven't been tampered with by the user.
 */
@RestController
@RequiredArgsConstructor
public class OidcAuthorizationController {

    private final TenantRepository tenantRepository;
    private final UserRepository userRepository;
    private final OidcClientRepository clientRepository;
    private final OidcAuthorizationService authorizationService;
    private final OidcTokenService tokenService;
    private final PublicHostProperties publicHost;

    @GetMapping("/t/{slug}/oauth2/authorize")
    public ResponseEntity<?> authorize(@PathVariable String slug,
                                       @RequestParam("response_type") String responseType,
                                       @RequestParam("client_id") String clientId,
                                       @RequestParam("redirect_uri") String redirectUri,
                                       @RequestParam("scope") String scope,
                                       @RequestParam(value = "state", required = false) String state,
                                       @RequestParam(value = "nonce", required = false) String nonce,
                                       @RequestParam(value = "code_challenge", required = false) String codeChallenge,
                                       @RequestParam(value = "code_challenge_method", required = false) String codeChallengeMethod,
                                       @AuthenticationPrincipal String email,
                                       HttpServletRequest request) {
        if (!"code".equals(responseType)) {
            throw new OidcAuthorizationException("unsupported_response_type",
                    "Only response_type=code is supported");
        }
        Tenant tenant = tenantRepository.findBySlug(slug)
                .orElseThrow(() -> new EntityNotFoundException("Unknown tenant"));

        // ---- Step 1: not authenticated → redirect to login ---------
        // Spring Security materialises the principal as the string
        // "anonymousUser" for unauthenticated requests (see
        // AnonymousAuthenticationToken), so a null/blank check alone
        // misses the common case of an unauthenticated browser.
        if (email == null || email.isBlank() || "anonymousUser".equals(email)) {
            String returnTo = currentUrl(request);
            String encoded = Base64.getUrlEncoder().withoutPadding()
                    .encodeToString(returnTo.getBytes(StandardCharsets.UTF_8));
            // Send the user to the tenant's own subdomain so the
            // TenantResolverFilter picks up the slug from Host and password
            // managers see acme.sso.weldforge.org as a distinct site.
            // Trailing slash matches the nginx /login/ proxy block so the
            // browser doesn't pick up a 301 → /login/ on the way through.
            String loginUrl = publicHost.originForTenant(slug)
                    + "/login/?oidcReturnTo=" + encoded;
            return ResponseEntity.status(302).location(URI.create(loginUrl)).build();
        }

        User user = userRepository.findByTenant_SlugAndEmailIgnoreCase(slug, email)
                .orElseThrow(() -> new EntityNotFoundException("User not in tenant"));

        OidcClient client = clientRepository.findByTenantIdAndClientId(tenant.getId(), clientId)
                .orElseThrow(() -> new OidcAuthorizationException("invalid_client",
                        "Unknown client_id for this tenant"));

        if (!client.getRedirectUriList().contains(redirectUri)) {
            throw new OidcAuthorizationException("invalid_request",
                    "redirect_uri does not match a registered URI");
        }

        // ---- Step 2: render consent ---------------------------------
        String html = renderConsent(slug, user, client, redirectUri, scope, state, nonce,
                codeChallenge, codeChallengeMethod);
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_TYPE, MediaType.TEXT_HTML_VALUE + "; charset=UTF-8")
                .body(html);
    }

    /**
     * Consent decision. The form posts back every parameter from the
     * original /authorize request as hidden inputs so we can re-construct
     * the {@link AuthorizeRequest} without keeping server-side state.
     */
    @PostMapping(value = "/t/{slug}/oauth2/authorize/decide",
                 consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    public ResponseEntity<Void> decide(@PathVariable String slug,
                                       @RequestParam("decision") String decision,
                                       @RequestParam("client_id") String clientId,
                                       @RequestParam("redirect_uri") String redirectUri,
                                       @RequestParam("scope") String scope,
                                       @RequestParam(value = "state", required = false) String state,
                                       @RequestParam(value = "nonce", required = false) String nonce,
                                       @RequestParam(value = "code_challenge", required = false) String codeChallenge,
                                       @RequestParam(value = "code_challenge_method", required = false) String codeChallengeMethod,
                                       @AuthenticationPrincipal String email) {
        Tenant tenant = tenantRepository.findBySlug(slug)
                .orElseThrow(() -> new EntityNotFoundException("Unknown tenant"));
        if (email == null || email.isBlank()) {
            throw new OidcAuthorizationException("login_required",
                    "Session expired before consent — please log in again");
        }
        User user = userRepository.findByTenant_SlugAndEmailIgnoreCase(slug, email)
                .orElseThrow(() -> new EntityNotFoundException("User not in tenant"));

        if (!"allow".equals(decision)) {
            // Per RFC 6749 §4.1.2.1, deny redirects back with an error.
            String url = appendQuery(redirectUri,
                    "error", "access_denied",
                    "error_description", "User denied the request",
                    "state", state);
            return ResponseEntity.status(302).location(URI.create(url)).build();
        }

        AuthorizeRequest req = new AuthorizeRequest(
                clientId, redirectUri,
                Arrays.stream(scope.split("\\s+")).filter(s -> !s.isBlank()).toList(),
                state, nonce, codeChallenge, codeChallengeMethod);
        String code = authorizationService.issueAuthorizationCode(tenant, user, req);

        String url = appendQuery(redirectUri, "code", code, "state", state);
        return ResponseEntity.status(302).location(URI.create(url)).build();
    }

    /**
     * Token endpoint — handles {@code authorization_code} (PKCE) and
     * {@code client_credentials}. Form-encoded per the spec.
     */
    @PostMapping(value = "/t/{slug}/oauth2/token", consumes = "application/x-www-form-urlencoded")
    public ResponseEntity<Map<String, Object>> token(@PathVariable String slug,
                                                     @RequestParam("grant_type") String grantType,
                                                     @RequestParam(value = "code", required = false) String code,
                                                     @RequestParam(value = "redirect_uri", required = false) String redirectUri,
                                                     @RequestParam(value = "client_id", required = false) String clientId,
                                                     @RequestParam(value = "client_secret", required = false) String clientSecret,
                                                     @RequestParam(value = "code_verifier", required = false) String codeVerifier,
                                                     @RequestParam(value = "scope", required = false) String scope,
                                                     HttpServletRequest request) {
        Tenant tenant = tenantRepository.findBySlug(slug)
                .orElseThrow(() -> new EntityNotFoundException("Unknown tenant"));
        String issuer = OidcDiscoveryControllerHelper.tenantIssuer(request, tenant.getSlug());

        return switch (grantType) {
            case "authorization_code" -> {
                CodeExchangeResult result = authorizationService.exchangeCode(tenant,
                        new CodeExchangeRequest(code, clientId, clientSecret, redirectUri, codeVerifier));
                IssuedTokens tokens = tokenService.issueForCodeExchange(
                        tenant, result.client(), result.user(),
                        result.scopes(), result.nonce(), issuer);
                yield ResponseEntity.ok(buildResponse(tokens, result.scopes()));
            }
            case "client_credentials" -> {
                OidcClient client = authorizationService.verifyClientCredentials(tenant, clientId, clientSecret);
                List<String> scopes = scope == null
                        ? client.getScopeList()
                        : Arrays.stream(scope.split("\\s+")).filter(s -> !s.isBlank()).toList();
                String accessToken = tokenService.issueForClientCredentials(tenant, client, scopes, issuer);
                yield ResponseEntity.ok(Map.of(
                        "access_token", accessToken,
                        "token_type",   "Bearer",
                        "expires_in",   3600,
                        "scope",        String.join(" ", scopes)
                ));
            }
            default -> throw new OidcAuthorizationException("unsupported_grant_type",
                    "grant_type " + grantType + " is not supported");
        };
    }

    @ExceptionHandler(OidcAuthorizationException.class)
    public ResponseEntity<Map<String, String>> handle(OidcAuthorizationException ex) {
        Map<String, String> body = new LinkedHashMap<>();
        body.put("error", ex.getErrorCode());
        body.put("error_description", ex.getMessage());
        return ResponseEntity.status(400).body(body);
    }

    // ---- Helpers -----------------------------------------------------

    private static Map<String, Object> buildResponse(IssuedTokens tokens, List<String> scopes) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("access_token", tokens.accessToken());
        body.put("token_type",   "Bearer");
        body.put("expires_in",   tokens.expiresIn());
        body.put("id_token",     tokens.idToken());
        body.put("scope",        String.join(" ", scopes));
        return body;
    }

    private static String currentUrl(HttpServletRequest request) {
        StringBuilder sb = new StringBuilder(request.getRequestURL());
        if (request.getQueryString() != null) sb.append('?').append(request.getQueryString());
        return sb.toString();
    }

    private static String appendQuery(String base, String... kv) {
        StringBuilder sb = new StringBuilder(base);
        boolean first = !base.contains("?");
        for (int i = 0; i + 1 < kv.length; i += 2) {
            String value = kv[i + 1];
            if (value == null || value.isBlank()) continue;
            sb.append(first ? '?' : '&');
            sb.append(URLEncoder.encode(kv[i], StandardCharsets.UTF_8));
            sb.append('=');
            sb.append(URLEncoder.encode(value, StandardCharsets.UTF_8));
            first = false;
        }
        return sb.toString();
    }

    /**
     * Render the consent screen as a single self-contained HTML document.
     * Inline styles match the WeldForge dark palette so it doesn't look
     * like a stranger pretending to be us.
     *
     * Every parameter from the original /authorize request becomes a
     * hidden form field — the consent decision endpoint reconstructs the
     * full request from those fields, so the server keeps no per-user
     * state in between.
     */
    private static String renderConsent(String slug, User user, OidcClient client, String redirectUri,
                                        String scope, String state, String nonce,
                                        String codeChallenge, String codeChallengeMethod) {
        String appName = client.getName() != null && !client.getName().isBlank()
                ? client.getName() : client.getClientId();
        String scopesHtml = Arrays.stream(scope.split("\\s+"))
                .filter(s -> !s.isBlank())
                .map(s -> "<li>" + escape(s) + "</li>")
                .reduce("", String::concat);

        return "<!doctype html><html><head><meta charset=\"UTF-8\">"
                + "<title>Authorize " + escape(appName) + "</title>"
                + "<style>"
                + "body{margin:0;font-family:'DM Sans',sans-serif;background:#070B17;color:#EEF2FF;display:flex;align-items:center;justify-content:center;min-height:100vh;}"
                + ".card{background:#0C1020;border:1px solid #1C2646;border-radius:4px;padding:32px 36px;width:100%;max-width:440px;box-shadow:0 20px 60px rgba(0,0,0,.4);}"
                + "h1{font-family:'Syne',sans-serif;font-size:22px;margin:0 0 6px;}"
                + ".eyebrow{font-family:'Space Mono',monospace;font-size:11px;letter-spacing:.2em;text-transform:uppercase;color:#E8921F;margin-bottom:8px;}"
                + ".sub{color:#8899CC;font-size:13px;margin:0 0 20px;}"
                + ".user{font-family:'Space Mono',monospace;font-size:12px;color:#8899CC;margin-bottom:20px;}"
                + ".scopes{background:#070B17;border:1px solid #1C2646;border-radius:3px;padding:14px 18px;margin:0 0 24px;}"
                + ".scopes h3{font-family:'Space Mono',monospace;font-size:10px;letter-spacing:.15em;text-transform:uppercase;color:#8899CC;margin:0 0 8px;}"
                + ".scopes ul{margin:0;padding-left:18px;font-size:13px;}"
                + ".actions{display:flex;gap:10px;}"
                + "button{flex:1;padding:12px;border-radius:3px;border:none;font-family:'Syne',sans-serif;font-weight:700;letter-spacing:.05em;text-transform:uppercase;font-size:12px;cursor:pointer;}"
                + ".allow{background:#4A8FF5;color:#fff;}"
                + ".deny{background:transparent;color:#8899CC;border:1px solid #243058;}"
                + "</style></head><body>"
                + "<div class=\"card\">"
                + "<div class=\"eyebrow\">// authorize</div>"
                + "<h1>" + escape(appName) + " wants to access your account</h1>"
                + "<p class=\"sub\">Hosted by tenant <strong>" + escape(slug) + "</strong>.</p>"
                + "<p class=\"user\">signed in as " + escape(user.getEmail()) + "</p>"
                + "<div class=\"scopes\"><h3>Requested permissions</h3><ul>" + scopesHtml + "</ul></div>"
                + "<form method=\"post\" action=\"/t/" + escape(slug) + "/oauth2/authorize/decide\">"
                + hidden("client_id", client.getClientId())
                + hidden("redirect_uri", redirectUri)
                + hidden("scope", scope)
                + hidden("state", state)
                + hidden("nonce", nonce)
                + hidden("code_challenge", codeChallenge)
                + hidden("code_challenge_method", codeChallengeMethod)
                + "<div class=\"actions\">"
                + "<button class=\"deny\" type=\"submit\" name=\"decision\" value=\"deny\">Deny</button>"
                + "<button class=\"allow\" type=\"submit\" name=\"decision\" value=\"allow\">Allow</button>"
                + "</div></form></div></body></html>";
    }

    private static String hidden(String name, String value) {
        if (value == null) value = "";
        return "<input type=\"hidden\" name=\"" + escape(name) + "\" value=\"" + escape(value) + "\">";
    }

    private static String escape(String s) {
        if (s == null) return "";
        return s.replace("&", "&amp;").replace("<", "&lt;")
                .replace(">", "&gt;").replace("\"", "&quot;");
    }
}
