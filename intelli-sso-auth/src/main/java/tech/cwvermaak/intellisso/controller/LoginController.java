package tech.cwvermaak.intellisso.controller;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.web.bind.annotation.*;
import tech.cwvermaak.intellisso.model.Tenant;
import tech.cwvermaak.intellisso.model.dto.AuthResponseDto;
import tech.cwvermaak.intellisso.model.dto.LoginRequestDto;
import tech.cwvermaak.intellisso.repository.TenantRepository;
import tech.cwvermaak.intellisso.service.AuthService;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * Hosted login form that closes the OIDC redirect loop.
 *
 * <p>The {@code OidcAuthorizationController} sends unauthenticated callers
 * to {@code /login?tenant=<slug>&oidcReturnTo=<base64-url>}. This
 * controller renders an HTML form, accepts the credentials POST, calls
 * {@link AuthService#login} (which sets the {@code wf_session} cookie via
 * {@code writeSessionCookie}), and 302s back to {@code oidcReturnTo}. The
 * second pass through {@code /oauth2/authorize} now sees an authenticated
 * principal and renders the consent screen.</p>
 *
 * <p>Open-redirect protection: the {@code oidcReturnTo} target is required
 * to be a path on the same origin (starts with {@code /}) — never an
 * absolute URL pointing elsewhere. Anything else is rejected.</p>
 */
@RestController
@RequiredArgsConstructor
public class LoginController {

    private final AuthService authService;
    private final TenantRepository tenantRepository;

    @GetMapping(value = {"/login", "/login/"}, produces = MediaType.TEXT_HTML_VALUE)
    public ResponseEntity<String> form(@RequestParam(value = "oidcReturnTo", required = false) String oidcReturnTo,
                                        @RequestParam(value = "tenant", required = false) String tenantSlug,
                                        @RequestParam(value = "error", required = false) String error) {
        Tenant tenant = resolveTenant(tenantSlug);
        String tenantLabel = tenant == null ? "Weldforge" : tenant.getDisplayName() != null
                ? tenant.getDisplayName() : tenant.getName();
        String html = renderForm(tenantLabel, tenantSlug, oidcReturnTo, error);
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_TYPE, MediaType.TEXT_HTML_VALUE + "; charset=UTF-8")
                .body(html);
    }

    @PostMapping(value = {"/login", "/login/"},
                 consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE,
                 produces = MediaType.TEXT_HTML_VALUE)
    public ResponseEntity<?> submit(@RequestParam("identifier") String identifier,
                                     @RequestParam("password") String password,
                                     @RequestParam(value = "tenant", required = false) String tenantSlug,
                                     @RequestParam(value = "oidcReturnTo", required = false) String oidcReturnTo,
                                     HttpServletRequest httpRequest,
                                     HttpServletResponse httpResponse) {
        AuthResponseDto auth;
        try {
            auth = authService.login(
                    new LoginRequestDto(identifier, password), httpRequest, httpResponse);
        } catch (BadCredentialsException ex) {
            return rerenderForm(tenantSlug, oidcReturnTo, "Invalid email or password.");
        } catch (RuntimeException ex) {
            return rerenderForm(tenantSlug, oidcReturnTo, "Sign-in failed: " + ex.getMessage());
        }

        if (auth.isMfaRequired() || auth.isMustEnrollMfa()) {
            // Hosted-login MFA flow not yet wired. Tell the user clearly.
            return rerenderForm(tenantSlug, oidcReturnTo,
                    "Multi-factor authentication is required for this account but the hosted "
                  + "login flow does not yet support MFA. Use the API flow instead.");
        }

        // AuthService.login already wrote the wf_session cookie. Just bounce
        // back to the original /oauth2/authorize URL — the next pass will
        // see the cookie via JwtAuthenticationFilter and render consent.
        String safeReturn = sanitiseReturnTo(oidcReturnTo);
        return ResponseEntity.status(302).location(URI.create(safeReturn)).build();
    }

    // ─────────────────────── helpers ──────────────────────────

    /** Decode the base64url return-to URL and accept only same-origin paths. */
    private String sanitiseReturnTo(String oidcReturnTo) {
        if (oidcReturnTo == null || oidcReturnTo.isBlank()) return "/";
        String decoded;
        try {
            decoded = new String(Base64.getUrlDecoder().decode(oidcReturnTo), StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            return "/";
        }
        // Allow /t/{slug}/oauth2/authorize?... — the OIDC return URL — and
        // reject anything that isn't a same-origin path. Absolute URLs are
        // refused so a malicious oidcReturnTo can't redirect off-site.
        try {
            URI u = URI.create(decoded);
            if (u.isAbsolute()) {
                // We accept absolute URLs that point at this host's /t/{slug}/...
                // path because /authorize generates them that way (currentUrl
                // builds an absolute URL). Strip down to path + query only.
                String path = u.getPath() != null ? u.getPath() : "/";
                if (!path.startsWith("/t/")) return "/";
                return path + (u.getRawQuery() != null ? "?" + u.getRawQuery() : "");
            }
            return decoded.startsWith("/") ? decoded : "/";
        } catch (IllegalArgumentException e) {
            return "/";
        }
    }

    private Tenant resolveTenant(String slug) {
        if (slug == null || slug.isBlank()) return null;
        return tenantRepository.findBySlug(slug).orElse(null);
    }

    private ResponseEntity<String> rerenderForm(String tenantSlug, String oidcReturnTo, String error) {
        Tenant tenant = resolveTenant(tenantSlug);
        String label = tenant == null ? "Weldforge" : tenant.getDisplayName() != null
                ? tenant.getDisplayName() : tenant.getName();
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_TYPE, MediaType.TEXT_HTML_VALUE + "; charset=UTF-8")
                .body(renderForm(label, tenantSlug, oidcReturnTo, error));
    }

    private String renderForm(String tenantLabel, String tenantSlug, String oidcReturnTo, String error) {
        String safeLabel = escape(tenantLabel);
        String safeSlug = escape(tenantSlug);
        String safeReturn = escape(oidcReturnTo);
        String errBlock = (error == null || error.isBlank()) ? ""
                : "<div class='wf-err'>" + escape(error) + "</div>";

        return "<!doctype html>\n"
            + "<html lang='en'><head>\n"
            + "  <meta charset='utf-8'>\n"
            + "  <meta name='viewport' content='width=device-width,initial-scale=1'>\n"
            + "  <title>Sign in — " + safeLabel + "</title>\n"
            + "  <style>\n"
            + "    body { margin: 0; font-family: system-ui, -apple-system, 'Segoe UI', sans-serif;\n"
            + "           background: #f7f5ef; color: #1a2b2b; min-height: 100vh; }\n"
            + "    .wf-card { max-width: 380px; margin: 5rem auto 2rem; padding: 2rem 1.75rem;\n"
            + "               background: #fff; border: 1px solid #e3e1db; border-radius: 12px;\n"
            + "               box-shadow: 0 8px 24px rgba(26,43,43,0.06); }\n"
            + "    h1 { font-size: 22px; margin: 0 0 .25rem; font-weight: 600; }\n"
            + "    .wf-sub { color: #4f6363; font-size: 14px; margin: 0 0 1.5rem; }\n"
            + "    form { display: flex; flex-direction: column; gap: 1rem; }\n"
            + "    label { display: flex; flex-direction: column; gap: .35rem; font-size: 14px; }\n"
            + "    input { font: inherit; padding: .6rem .75rem; border: 1px solid #e3e1db;\n"
            + "            border-radius: 8px; background: #fff; }\n"
            + "    input:focus { outline: 2px solid #3a9a77; outline-offset: 1px; }\n"
            + "    button { margin-top: .25rem; padding: .7rem 1rem; background: #2e7d5f; color: #fff;\n"
            + "             border: 0; border-radius: 8px; font: inherit; font-weight: 600; cursor: pointer; }\n"
            + "    button:hover { background: #1f5a44; }\n"
            + "    .wf-err { background: #fdecee; color: #b7424a; border: 1px solid #f3c4c8;\n"
            + "              border-radius: 8px; padding: .6rem .75rem; margin-bottom: 1rem; font-size: 14px; }\n"
            + "    .wf-foot { color: #4f6363; font-size: 12px; text-align: center; margin-top: 1.5rem; }\n"
            + "  </style>\n"
            + "</head><body>\n"
            + "<section class='wf-card'>\n"
            + "  <h1>Sign in to " + safeLabel + "</h1>\n"
            + "  <p class='wf-sub'>Use your Weldforge credentials.</p>\n"
            + errBlock
            + "  <form method='post' action='/login/' autocomplete='on'>\n"
            + "    <input type='hidden' name='tenant' value='" + safeSlug + "'>\n"
            + "    <input type='hidden' name='oidcReturnTo' value='" + safeReturn + "'>\n"
            + "    <label><span>Email or username</span>\n"
            + "      <input type='text' name='identifier' autocomplete='username' required autofocus></label>\n"
            + "    <label><span>Password</span>\n"
            + "      <input type='password' name='password' autocomplete='current-password' required></label>\n"
            + "    <button type='submit'>Sign in</button>\n"
            + "  </form>\n"
            + "</section>\n"
            + "<p class='wf-foot'>Powered by Weldforge.</p>\n"
            + "</body></html>\n";
    }

    private static String escape(String s) {
        if (s == null) return "";
        return s.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;")
                .replace("'", "&#39;");
    }
}
