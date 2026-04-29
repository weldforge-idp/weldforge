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
import tech.cwvermaak.intellisso.service.PasswordResetService;

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
    private final PasswordResetService passwordResetService;

    // ────────────────────────────── /login/ ──────────────────────────────

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

    // ──────────────────────── /login/forgot ──────────────────────────────

    @GetMapping(value = "/login/forgot", produces = MediaType.TEXT_HTML_VALUE)
    public ResponseEntity<String> forgotForm(@RequestParam(value = "tenant", required = false) String tenantSlug,
                                              @RequestParam(value = "sent", required = false) String sent) {
        Tenant tenant = resolveTenant(tenantSlug);
        String label = tenant == null ? "Weldforge"
                : tenant.getDisplayName() != null ? tenant.getDisplayName() : tenant.getName();
        String html = sent != null
                ? renderSent(label, tenantSlug)
                : renderForgotForm(label, tenantSlug, null);
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_TYPE, MediaType.TEXT_HTML_VALUE + "; charset=UTF-8")
                .body(html);
    }

    @PostMapping(value = "/login/forgot",
                 consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE,
                 produces = MediaType.TEXT_HTML_VALUE)
    public ResponseEntity<?> forgotSubmit(@RequestParam("identifier") String identifier,
                                           @RequestParam(value = "tenant", required = false) String tenantSlug) {
        try {
            // requestReset is privacy-preserving: it never throws "user not
            // found" — always 200 + always render the same "if that
            // address is registered…" page.
            passwordResetService.requestReset(identifier);
        } catch (RuntimeException e) {
            // Swallow — same response for any failure mode.
        }
        return ResponseEntity.status(303)
                .location(URI.create("/login/forgot?sent=1"
                        + (tenantSlug == null ? "" : "&tenant=" + tenantSlug)))
                .build();
    }

    // ──────────────────────── /login/reset ───────────────────────────────

    @GetMapping(value = "/login/reset", produces = MediaType.TEXT_HTML_VALUE)
    public ResponseEntity<String> resetForm(@RequestParam("token") String token,
                                             @RequestParam(value = "tenant", required = false) String tenantSlug,
                                             @RequestParam(value = "error", required = false) String error) {
        Tenant tenant = resolveTenant(tenantSlug);
        String label = tenant == null ? "Weldforge"
                : tenant.getDisplayName() != null ? tenant.getDisplayName() : tenant.getName();
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_TYPE, MediaType.TEXT_HTML_VALUE + "; charset=UTF-8")
                .body(renderResetForm(label, tenantSlug, token, error));
    }

    @PostMapping(value = "/login/reset",
                 consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE,
                 produces = MediaType.TEXT_HTML_VALUE)
    public ResponseEntity<?> resetSubmit(@RequestParam("token") String token,
                                          @RequestParam("newPassword") String newPassword,
                                          @RequestParam("confirmPassword") String confirmPassword,
                                          @RequestParam(value = "tenant", required = false) String tenantSlug) {
        if (newPassword == null || newPassword.length() < 8) {
            return rerenderReset(tenantSlug, token, "Password must be at least 8 characters.");
        }
        if (!newPassword.equals(confirmPassword)) {
            return rerenderReset(tenantSlug, token, "Passwords do not match.");
        }
        try {
            passwordResetService.resetPassword(token, newPassword);
        } catch (RuntimeException e) {
            return rerenderReset(tenantSlug, token,
                    "Reset link is invalid or has expired. Request a new one.");
        }
        // Success — bounce to /login/ so the user can sign in with the new password.
        return ResponseEntity.status(303)
                .location(URI.create("/login/?tenant=" + (tenantSlug == null ? "" : tenantSlug)
                        + "&reset=1")).build();
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
            + "  <p style='margin-top:1rem;font-size:13px;text-align:center;'>"
            + "<a href='/login/forgot?tenant=" + safeSlug + "' style='color:#2e7d5f;'>Forgot your password?</a></p>\n"
            + "</section>\n"
            + "<p class='wf-foot'>Powered by Weldforge.</p>\n"
            + "</body></html>\n";
    }

    private ResponseEntity<String> rerenderReset(String tenantSlug, String token, String error) {
        Tenant tenant = resolveTenant(tenantSlug);
        String label = tenant == null ? "Weldforge"
                : tenant.getDisplayName() != null ? tenant.getDisplayName() : tenant.getName();
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_TYPE, MediaType.TEXT_HTML_VALUE + "; charset=UTF-8")
                .body(renderResetForm(label, tenantSlug, token, error));
    }

    private String renderForgotForm(String tenantLabel, String tenantSlug, String error) {
        String safeLabel = escape(tenantLabel);
        String safeSlug = escape(tenantSlug);
        String errBlock = error == null || error.isBlank() ? ""
                : "<div class='wf-err'>" + escape(error) + "</div>";
        return chrome("Reset password — " + safeLabel,
            "<section class='wf-card'>"
          + "<h1>Reset password</h1>"
          + "<p class='wf-sub'>Enter your email and we'll send you a link to choose a new password.</p>"
          + errBlock
          + "<form method='post' action='/login/forgot' autocomplete='on'>"
          + "  <input type='hidden' name='tenant' value='" + safeSlug + "'>"
          + "  <label><span>Email</span>"
          + "    <input type='email' name='identifier' autocomplete='username' required autofocus></label>"
          + "  <button type='submit'>Send reset link</button>"
          + "</form>"
          + "<p style='margin-top:1rem;font-size:13px;text-align:center;'>"
          + "<a href='/login/?tenant=" + safeSlug + "' style='color:#2e7d5f;'>← Back to sign in</a></p>"
          + "</section>");
    }

    private String renderSent(String tenantLabel, String tenantSlug) {
        String safeSlug = escape(tenantSlug);
        return chrome("Reset link sent — " + escape(tenantLabel),
            "<section class='wf-card'>"
          + "<h1>Check your inbox</h1>"
          + "<p class='wf-sub'>If that email is registered, a password-reset link is on its way. "
          + "It expires in 30 minutes.</p>"
          + "<p style='margin-top:1.5rem;text-align:center;'>"
          + "<a href='/login/?tenant=" + safeSlug + "' style='color:#2e7d5f;'>← Back to sign in</a></p>"
          + "</section>");
    }

    private String renderResetForm(String tenantLabel, String tenantSlug, String token, String error) {
        String safeLabel = escape(tenantLabel);
        String safeSlug = escape(tenantSlug);
        String safeToken = escape(token);
        String errBlock = error == null || error.isBlank() ? ""
                : "<div class='wf-err'>" + escape(error) + "</div>";
        return chrome("Choose a new password — " + safeLabel,
            "<section class='wf-card'>"
          + "<h1>Choose a new password</h1>"
          + "<p class='wf-sub'>At least 8 characters. Use something you don't use anywhere else.</p>"
          + errBlock
          + "<form method='post' action='/login/reset' autocomplete='on'>"
          + "  <input type='hidden' name='tenant' value='" + safeSlug + "'>"
          + "  <input type='hidden' name='token' value='" + safeToken + "'>"
          + "  <label><span>New password</span>"
          + "    <input type='password' name='newPassword' minlength='8' autocomplete='new-password' required autofocus></label>"
          + "  <label><span>Confirm password</span>"
          + "    <input type='password' name='confirmPassword' minlength='8' autocomplete='new-password' required></label>"
          + "  <button type='submit'>Set new password</button>"
          + "</form>"
          + "</section>");
    }

    /** Common page chrome — same look as the login form. */
    private String chrome(String title, String inner) {
        return "<!doctype html>\n<html lang='en'><head>"
            + "<meta charset='utf-8'>"
            + "<meta name='viewport' content='width=device-width,initial-scale=1'>"
            + "<title>" + title + "</title>"
            + "<style>"
            + "body{margin:0;font-family:system-ui,-apple-system,'Segoe UI',sans-serif;"
            + "background:#f7f5ef;color:#1a2b2b;min-height:100vh;}"
            + ".wf-card{max-width:380px;margin:5rem auto 2rem;padding:2rem 1.75rem;"
            + "background:#fff;border:1px solid #e3e1db;border-radius:12px;"
            + "box-shadow:0 8px 24px rgba(26,43,43,0.06);}"
            + "h1{font-size:22px;margin:0 0 .25rem;font-weight:600;}"
            + ".wf-sub{color:#4f6363;font-size:14px;margin:0 0 1.5rem;}"
            + "form{display:flex;flex-direction:column;gap:1rem;}"
            + "label{display:flex;flex-direction:column;gap:.35rem;font-size:14px;}"
            + "input{font:inherit;padding:.6rem .75rem;border:1px solid #e3e1db;"
            + "border-radius:8px;background:#fff;}"
            + "input:focus{outline:2px solid #3a9a77;outline-offset:1px;}"
            + "button{margin-top:.25rem;padding:.7rem 1rem;background:#2e7d5f;color:#fff;"
            + "border:0;border-radius:8px;font:inherit;font-weight:600;cursor:pointer;}"
            + "button:hover{background:#1f5a44;}"
            + ".wf-err{background:#fdecee;color:#b7424a;border:1px solid #f3c4c8;"
            + "border-radius:8px;padding:.6rem .75rem;margin-bottom:1rem;font-size:14px;}"
            + "</style></head><body>"
            + inner
            + "<p style='color:#4f6363;font-size:12px;text-align:center;margin-top:1.5rem;'>Powered by Weldforge.</p>"
            + "</body></html>";
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
