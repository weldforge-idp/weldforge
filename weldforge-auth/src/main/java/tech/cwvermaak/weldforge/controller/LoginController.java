package tech.cwvermaak.weldforge.controller;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.web.bind.annotation.*;
import tech.cwvermaak.weldforge.config.tenant.PublicHostProperties;
import tech.cwvermaak.weldforge.config.tenant.TenantContext;
import tech.cwvermaak.weldforge.model.Tenant;
import tech.cwvermaak.weldforge.model.dto.AuthResponseDto;
import tech.cwvermaak.weldforge.model.dto.LoginRequestDto;
import tech.cwvermaak.weldforge.repository.TenantRepository;
import tech.cwvermaak.weldforge.service.AuthService;
import tech.cwvermaak.weldforge.service.PasswordResetService;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;

/**
 * Hosted login form that closes the OIDC redirect loop.
 *
 * <p>The {@code OidcAuthorizationController} sends unauthenticated callers
 * to {@code https://{slug}.<base-domain>/login/?oidcReturnTo=<base64-url>} —
 * the per-tenant subdomain so password managers see each tenant as a
 * distinct site. {@code TenantResolverFilter} maps the Host header to the
 * slug; this controller picks it up via {@link TenantContext} and never
 * accepts a {@code tenant} query parameter. See
 * {@code docs/auth-url-spec.md}.</p>
 *
 * <p>The credential POST calls {@link AuthService#login} (which sets the
 * {@code wf_session} cookie via {@code writeSessionCookie}) and 302s back
 * to {@code oidcReturnTo}. The second pass through {@code /oauth2/authorize}
 * — on the apex host — sees the cookie via {@code JwtAuthenticationFilter}
 * and renders consent.</p>
 *
 * <p>Open-redirect protection: the {@code oidcReturnTo} target is required
 * to be a path on the same origin (starts with {@code /}) — never an
 * absolute URL pointing elsewhere. Anything else is rejected.</p>
 *
 * <p><b>Per-tenant branding.</b> All four pages (sign-in, forgot-password,
 * reset-link-sent, choose-new-password) render through the {@link #chrome}
 * shell, themed from {@code Tenant.branding}. A tenant with no branding gets
 * the WeldForge default (dark navy, shield logo, {@code #4A8FF5} blue). A
 * tenant whose branding map sets {@code theme}, {@code primaryColor},
 * {@code primaryHoverColor}, {@code appName}, {@code logoUrl} or
 * {@code tagline} gets a login screen that matches its own application —
 * so the OIDC hop is not a jarring change of brand mid-flow.</p>
 */
@RestController
@RequiredArgsConstructor
public class LoginController {

    private final AuthService authService;
    private final TenantRepository tenantRepository;
    private final PasswordResetService passwordResetService;
    private final PublicHostProperties publicHost;

    // ────────────────────────────── /login/ ──────────────────────────────

    @GetMapping(value = {"/login", "/login/"}, produces = MediaType.TEXT_HTML_VALUE)
    public ResponseEntity<String> form(@RequestParam(value = "oidcReturnTo", required = false) String oidcReturnTo,
                                        @RequestParam(value = "error", required = false) String error) {
        String tenantSlug = TenantContext.get();
        Tenant tenant = resolveTenant(tenantSlug);
        String html = renderForm(tenant, oidcReturnTo, error);
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_TYPE, MediaType.TEXT_HTML_VALUE + "; charset=UTF-8")
                .body(html);
    }

    @PostMapping(value = {"/login", "/login/"},
                 consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE,
                 produces = MediaType.TEXT_HTML_VALUE)
    public ResponseEntity<?> submit(@RequestParam("identifier") String identifier,
                                     @RequestParam("password") String password,
                                     @RequestParam(value = "oidcReturnTo", required = false) String oidcReturnTo,
                                     HttpServletRequest httpRequest,
                                     HttpServletResponse httpResponse) {
        AuthResponseDto auth;
        try {
            auth = authService.login(
                    new LoginRequestDto(identifier, password), httpRequest, httpResponse);
        } catch (BadCredentialsException ex) {
            return rerenderForm(oidcReturnTo, "Invalid email or password.");
        } catch (RuntimeException ex) {
            return rerenderForm(oidcReturnTo, "Sign-in failed: " + ex.getMessage());
        }

        if (auth.isMfaRequired() || auth.isMustEnrollMfa()) {
            // Hosted-login MFA flow not yet wired. Tell the user clearly.
            return rerenderForm(oidcReturnTo,
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
    public ResponseEntity<String> forgotForm(@RequestParam(value = "sent", required = false) String sent) {
        Tenant tenant = resolveTenant(TenantContext.get());
        String html = sent != null
                ? renderSent(tenant)
                : renderForgotForm(tenant, null);
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_TYPE, MediaType.TEXT_HTML_VALUE + "; charset=UTF-8")
                .body(html);
    }

    @PostMapping(value = "/login/forgot",
                 consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE,
                 produces = MediaType.TEXT_HTML_VALUE)
    public ResponseEntity<?> forgotSubmit(@RequestParam("identifier") String identifier) {
        try {
            // requestReset is privacy-preserving: it never throws "user not
            // found" — always 200 + always render the same "if that
            // address is registered…" page.
            passwordResetService.requestReset(identifier);
        } catch (RuntimeException e) {
            // Swallow — same response for any failure mode.
        }
        return ResponseEntity.status(303)
                .location(URI.create("/login/forgot?sent=1"))
                .build();
    }

    // ──────────────────────── /login/reset ───────────────────────────────

    @GetMapping(value = "/login/reset", produces = MediaType.TEXT_HTML_VALUE)
    public ResponseEntity<String> resetForm(@RequestParam("token") String token,
                                             @RequestParam(value = "error", required = false) String error) {
        Tenant tenant = resolveTenant(TenantContext.get());
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_TYPE, MediaType.TEXT_HTML_VALUE + "; charset=UTF-8")
                .body(renderResetForm(tenant, token, error));
    }

    @PostMapping(value = "/login/reset",
                 consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE,
                 produces = MediaType.TEXT_HTML_VALUE)
    public ResponseEntity<?> resetSubmit(@RequestParam("token") String token,
                                          @RequestParam("newPassword") String newPassword,
                                          @RequestParam("confirmPassword") String confirmPassword) {
        if (newPassword == null || newPassword.length() < 8) {
            return rerenderReset(token, "Password must be at least 8 characters.");
        }
        if (!newPassword.equals(confirmPassword)) {
            return rerenderReset(token, "Passwords do not match.");
        }
        try {
            passwordResetService.resetPassword(token, newPassword);
        } catch (RuntimeException e) {
            return rerenderReset(token,
                    "Reset link is invalid or has expired. Request a new one.");
        }
        // Success — bounce to /login/ so the user can sign in with the new password.
        return ResponseEntity.status(303)
                .location(URI.create("/login/?reset=1")).build();
    }

    // ─────────────────────── helpers ──────────────────────────

    /**
     * Decode the base64url return-to URL and accept only targets on our
     * own public domain. The OIDC bounce-back lands on the apex host
     * ({@code sso.weldforge.org/t/{slug}/oauth2/authorize?…}) while the
     * user is signing in on the tenant subdomain
     * ({@code {slug}.sso.weldforge.org/login}), so we must keep the
     * absolute URL — a relative redirect would land back on the
     * subdomain and miss the OIDC endpoint.
     */
    private String sanitiseReturnTo(String oidcReturnTo) {
        if (oidcReturnTo == null || oidcReturnTo.isBlank()) return "/";
        String decoded;
        try {
            decoded = new String(Base64.getUrlDecoder().decode(oidcReturnTo), StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            return "/";
        }
        try {
            URI u = URI.create(decoded);
            if (u.isAbsolute()) {
                String host = u.getHost();
                String path = u.getPath() != null ? u.getPath() : "/";
                if (!path.startsWith("/t/")) return "/";
                String base = publicHost.getBaseDomain();
                if (host == null || base == null) return "/";
                // OIDC bounce-back is ONLY ever to the apex host's
                // /t/{slug}/oauth2/authorize endpoint. Accepting any
                // subdomain here would let an attacker who controls a
                // tenant subdomain trick a victim into sending their
                // (cross-domain-scoped) session cookie to that subdomain
                // mid-flow. Apex-only closes that.
                if (!host.equalsIgnoreCase(base)) return "/";
                return decoded;
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

    private ResponseEntity<String> rerenderForm(String oidcReturnTo, String error) {
        Tenant tenant = resolveTenant(TenantContext.get());
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_TYPE, MediaType.TEXT_HTML_VALUE + "; charset=UTF-8")
                .body(renderForm(tenant, oidcReturnTo, error));
    }

    private String renderForm(Tenant tenant, String oidcReturnTo, String error) {
        String safeLabel = escape(brandName(tenant));
        String safeReturn = escape(oidcReturnTo);
        String tagline = brandValue(tenant, "tagline");
        String sub = tagline != null ? escape(tagline)
                : "Use your WeldForge credentials to continue.";
        String errBlock = (error == null || error.isBlank()) ? ""
                : "<div class='wf-err'>" + escape(error) + "</div>";

        String inner =
              "<section class='wf-card'>\n"
            + "  <h1>Sign in to " + safeLabel + "</h1>\n"
            + "  <p class='wf-sub'>" + sub + "</p>\n"
            + errBlock
            + "  <form method='post' action='/login/' autocomplete='on'>\n"
            + "    <input type='hidden' name='oidcReturnTo' value='" + safeReturn + "'>\n"
            + "    <label><span>Email or username</span>\n"
            + "      <input type='text' name='identifier' autocomplete='username' required autofocus></label>\n"
            + "    <label><span>Password</span>\n"
            + "      <input type='password' name='password' autocomplete='current-password' required></label>\n"
            + "    <button type='submit'>Sign in</button>\n"
            + "  </form>\n"
            + "  <p class='wf-link'><a href='/login/forgot'>Forgot your password?</a></p>\n"
            + "</section>\n";
        return chrome(tenant, "Sign in — " + safeLabel, inner);
    }

    private ResponseEntity<String> rerenderReset(String token, String error) {
        Tenant tenant = resolveTenant(TenantContext.get());
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_TYPE, MediaType.TEXT_HTML_VALUE + "; charset=UTF-8")
                .body(renderResetForm(tenant, token, error));
    }

    private String renderForgotForm(Tenant tenant, String error) {
        String safeLabel = escape(brandName(tenant));
        String errBlock = error == null || error.isBlank() ? ""
                : "<div class='wf-err'>" + escape(error) + "</div>";
        return chrome(tenant, "Reset password — " + safeLabel,
            "<section class='wf-card'>"
          + "<h1>Reset password</h1>"
          + "<p class='wf-sub'>Enter your email and we'll send you a link to choose a new password.</p>"
          + errBlock
          + "<form method='post' action='/login/forgot' autocomplete='on'>"
          + "  <label><span>Email</span>"
          + "    <input type='email' name='identifier' autocomplete='username' required autofocus></label>"
          + "  <button type='submit'>Send reset link</button>"
          + "</form>"
          + "<p class='wf-link'><a href='/login/'>← Back to sign in</a></p>"
          + "</section>");
    }

    private String renderSent(Tenant tenant) {
        String safeLabel = escape(brandName(tenant));
        return chrome(tenant, "Reset link sent — " + safeLabel,
            "<section class='wf-card'>"
          + "<h1>Check your inbox</h1>"
          + "<p class='wf-sub'>If that email is registered, a password-reset link is on its way. "
          + "It expires in 30 minutes.</p>"
          + "<p class='wf-link'><a href='/login/'>← Back to sign in</a></p>"
          + "</section>");
    }

    private String renderResetForm(Tenant tenant, String token, String error) {
        String safeLabel = escape(brandName(tenant));
        String safeToken = escape(token);
        String errBlock = error == null || error.isBlank() ? ""
                : "<div class='wf-err'>" + escape(error) + "</div>";
        return chrome(tenant, "Choose a new password — " + safeLabel,
            "<section class='wf-card'>"
          + "<h1>Choose a new password</h1>"
          + "<p class='wf-sub'>At least 8 characters. Use something you don't use anywhere else.</p>"
          + errBlock
          + "<form method='post' action='/login/reset' autocomplete='on'>"
          + "  <input type='hidden' name='token' value='" + safeToken + "'>"
          + "  <label><span>New password</span>"
          + "    <input type='password' name='newPassword' minlength='8' autocomplete='new-password' required autofocus></label>"
          + "  <label><span>Confirm password</span>"
          + "    <input type='password' name='confirmPassword' minlength='8' autocomplete='new-password' required></label>"
          + "  <button type='submit'>Set new password</button>"
          + "</form>"
          + "</section>");
    }

    /**
     * Common page shell. Every hosted-login page renders through here so the
     * chrome — logo, palette, typography — stays in one place. The look is
     * resolved per tenant from {@code Tenant.branding}.
     */
    private String chrome(Tenant tenant, String title, String inner) {
        Look look = resolveLook(tenant);
        return "<!doctype html>\n<html lang='en'><head>"
            + "<meta charset='utf-8'>"
            + "<meta name='viewport' content='width=device-width,initial-scale=1'>"
            + "<title>" + title + "</title>"
            + (look.syne() ? FONT_LINK : "")
            + "<style>:root{" + look.rootCss() + "}" + BASE_CSS + "</style>"
            + "</head><body>"
            + "<div class='wf-logo'>" + look.logoHtml() + "</div>"
            + inner
            + "<p class='wf-foot'>Powered by <strong>WeldForge</strong></p>"
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

    // ─────────────────────── per-tenant branding ──────────────────────────

    /** Resolved presentation for one page render. */
    private record Look(String rootCss, boolean syne, String logoHtml) {}

    /**
     * The brand name shown in headings: the branding {@code appName} if set,
     * else the tenant's display name / name, else "WeldForge".
     */
    private static String brandName(Tenant tenant) {
        String appName = brandValue(tenant, "appName");
        if (appName != null) return appName;
        if (tenant == null) return "WeldForge";
        return tenant.getDisplayName() != null ? tenant.getDisplayName() : tenant.getName();
    }

    /** A single string-valued branding key, trimmed; null when absent/blank. */
    private static String brandValue(Tenant tenant, String key) {
        if (tenant == null || tenant.getBranding() == null) return null;
        Object v = tenant.getBranding().get(key);
        if (v == null) return null;
        String s = v.toString().trim();
        return s.isEmpty() ? null : s;
    }

    /**
     * Build the {@code :root} CSS-variable block, font choice and logo from a
     * tenant's branding map. No branding → WeldForge dark default.
     */
    private Look resolveLook(Tenant tenant) {
        Map<String, Object> b = tenant == null ? null : tenant.getBranding();
        boolean light = b != null && "light".equalsIgnoreCase(String.valueOf(b.get("theme")));

        StringBuilder root = new StringBuilder(light ? LIGHT_ROOT : DARK_ROOT);

        // Colour overrides — only honoured when a valid 6-digit hex is given,
        // so a malformed branding value can never break the stylesheet.
        String primary = hex(brandValue(tenant, "primaryColor"));
        if (primary != null) {
            String hover = hex(brandValue(tenant, "primaryHoverColor"));
            if (hover == null) hover = darken(primary, 0.85);
            root.append("--wf-primary:").append(primary).append(';')
                .append("--wf-primary-hover:").append(hover).append(';')
                .append("--wf-link:").append(primary).append(';')
                .append("--wf-focus-ring:").append(rgba(primary, "0.28")).append(';');
        }

        return new Look(root.toString(), !light, resolveLogo(tenant));
    }

    /**
     * Logo block: a tenant {@code logoUrl} image, else a text wordmark from
     * {@code appName}, else the inline WeldForge shield.
     */
    private String resolveLogo(Tenant tenant) {
        String logoUrl = brandValue(tenant, "logoUrl");
        if (logoUrl != null && (logoUrl.startsWith("https://") || logoUrl.startsWith("http://"))) {
            return "<img src='" + escape(logoUrl) + "' alt='" + escape(brandName(tenant)) + "'>";
        }
        String appName = brandValue(tenant, "appName");
        if (appName != null) {
            return "<div class='wf-wordmark'>" + escape(appName) + "</div>";
        }
        return LOGO_SVG;
    }

    /** Accept a #rrggbb hex colour; anything else → null (override ignored). */
    private static String hex(String s) {
        return (s != null && s.matches("#[0-9A-Fa-f]{6}")) ? s : null;
    }

    /** Multiply each channel of a #rrggbb colour by {@code f} (0..1). */
    private static String darken(String hexColour, double f) {
        int r = clamp((int) (Integer.parseInt(hexColour.substring(1, 3), 16) * f));
        int g = clamp((int) (Integer.parseInt(hexColour.substring(3, 5), 16) * f));
        int b = clamp((int) (Integer.parseInt(hexColour.substring(5, 7), 16) * f));
        return String.format("#%02X%02X%02X", r, g, b);
    }

    /** A #rrggbb colour expressed as rgba() with the given alpha. */
    private static String rgba(String hexColour, String alpha) {
        int r = Integer.parseInt(hexColour.substring(1, 3), 16);
        int g = Integer.parseInt(hexColour.substring(3, 5), 16);
        int b = Integer.parseInt(hexColour.substring(5, 7), 16);
        return "rgba(" + r + "," + g + "," + b + "," + alpha + ")";
    }

    private static int clamp(int v) {
        return v < 0 ? 0 : Math.min(v, 255);
    }

    // ─────────────────────── brand assets ──────────────────────────

    private static final String FONT_LINK =
        "<link rel='preconnect' href='https://fonts.googleapis.com'>"
      + "<link rel='preconnect' href='https://fonts.gstatic.com' crossorigin>"
      + "<link rel='stylesheet' "
      + "href='https://fonts.googleapis.com/css2?family=Syne:wght@600;700;800&display=swap'>";

    /** WeldForge default — dark navy, the marketing-site palette. */
    private static final String DARK_ROOT = """
        color-scheme: dark;
        --wf-font: system-ui,-apple-system,'Segoe UI',sans-serif;
        --wf-display-font: 'Syne',system-ui,sans-serif;
        --wf-bg: #070B17;
        --wf-bg-image: radial-gradient(900px 520px at 50% -8%, rgba(74,143,245,0.16), transparent 70%), linear-gradient(180deg,#0C1020 0%,#070B17 62%);
        --wf-surface: #0F1426;
        --wf-border: #222A44;
        --wf-text: #E6EBF5;
        --wf-heading: #F2F5FB;
        --wf-muted: #8B93A8;
        --wf-label: #C8D0E0;
        --wf-input-bg: #0A0E1C;
        --wf-input-border: #2A3354;
        --wf-primary: #4A8FF5;
        --wf-primary-hover: #5E9EFF;
        --wf-focus-ring: rgba(74,143,245,0.25);
        --wf-link: #6EA7FF;
        --wf-shadow: 0 18px 48px rgba(0,0,0,0.55);
        --wf-foot-strong: #6E7790;
        --wf-err-bg: rgba(255,107,107,0.10);
        --wf-err-border: rgba(255,107,107,0.32);
        --wf-err-text: #FF8D8D;
        """;

    /** Light surface for tenants whose own app is light-themed. */
    private static final String LIGHT_ROOT = """
        color-scheme: light;
        --wf-font: -apple-system,BlinkMacSystemFont,'Segoe UI','Roboto',sans-serif;
        --wf-display-font: -apple-system,BlinkMacSystemFont,'Segoe UI','Roboto',sans-serif;
        --wf-bg: #f3f4f6;
        --wf-bg-image: none;
        --wf-surface: #ffffff;
        --wf-border: #e5e7eb;
        --wf-text: #111827;
        --wf-heading: #111827;
        --wf-muted: #6b7280;
        --wf-label: #374151;
        --wf-input-bg: #ffffff;
        --wf-input-border: #d1d5db;
        --wf-primary: #4A8FF5;
        --wf-primary-hover: #2E63B0;
        --wf-focus-ring: rgba(74,143,245,0.25);
        --wf-link: #4A8FF5;
        --wf-shadow: 0 10px 30px rgba(17,24,39,0.08);
        --wf-foot-strong: #4b5563;
        --wf-err-bg: #fef2f2;
        --wf-err-border: #fecaca;
        --wf-err-text: #b91c1c;
        """;

    /** Theme-agnostic stylesheet — every colour comes from a {@code --wf-*} variable. */
    private static final String BASE_CSS = """
        * { box-sizing: border-box; }
        body {
          margin: 0; min-height: 100vh;
          font-family: var(--wf-font);
          color: var(--wf-text);
          background-color: var(--wf-bg);
          background-image: var(--wf-bg-image);
          display: flex; flex-direction: column; align-items: center;
        }
        .wf-logo { margin: 4.5rem 0 1.6rem; text-align: center; }
        .wf-logo svg, .wf-logo img { height: 46px; width: auto; display: block; }
        .wf-wordmark {
          font-family: var(--wf-display-font);
          font-size: 26px; font-weight: 800; letter-spacing: .3px;
          color: var(--wf-primary);
        }
        .wf-card {
          width: 384px; max-width: calc(100vw - 2rem);
          padding: 2rem 1.75rem;
          background: var(--wf-surface);
          border: 1px solid var(--wf-border);
          border-radius: 14px;
          box-shadow: var(--wf-shadow);
        }
        h1 {
          font-family: var(--wf-display-font);
          font-size: 22px; font-weight: 700; letter-spacing: .2px;
          margin: 0 0 .35rem; color: var(--wf-heading);
        }
        .wf-sub { color: var(--wf-muted); font-size: 14px; line-height: 1.5; margin: 0 0 1.5rem; }
        form { display: flex; flex-direction: column; gap: 1rem; }
        label { display: flex; flex-direction: column; gap: .4rem;
                font-size: 13px; color: var(--wf-label); }
        input {
          font: inherit; font-size: 14px;
          padding: .65rem .8rem;
          border: 1px solid var(--wf-input-border); border-radius: 9px;
          background: var(--wf-input-bg); color: var(--wf-text);
        }
        input::placeholder { color: var(--wf-muted); }
        input:focus {
          outline: none; border-color: var(--wf-primary);
          box-shadow: 0 0 0 3px var(--wf-focus-ring);
        }
        input:-webkit-autofill, input:-webkit-autofill:focus {
          -webkit-text-fill-color: var(--wf-text);
          -webkit-box-shadow: 0 0 0 100px var(--wf-input-bg) inset;
          caret-color: var(--wf-text);
        }
        button {
          margin-top: .35rem; padding: .72rem 1rem;
          background: var(--wf-primary); color: #fff;
          border: 0; border-radius: 9px;
          font: inherit; font-size: 14px; font-weight: 600;
          cursor: pointer; transition: background .15s ease;
        }
        button:hover { background: var(--wf-primary-hover); }
        a { color: var(--wf-link); text-decoration: none; }
        a:hover { text-decoration: underline; }
        .wf-link { margin-top: 1rem; font-size: 13px; text-align: center; }
        .wf-err {
          background: var(--wf-err-bg); color: var(--wf-err-text);
          border: 1px solid var(--wf-err-border); border-radius: 9px;
          padding: .6rem .75rem; margin-bottom: 1rem;
          font-size: 13px; line-height: 1.45;
        }
        .wf-foot { color: var(--wf-muted); font-size: 12px; margin: 1.5rem 0 2.5rem; }
        .wf-foot strong { color: var(--wf-foot-strong); font-weight: 600; }
        """;

    /** WeldForge shield wordmark, inlined so the default page has no asset dependency. */
    private static final String LOGO_SVG = """
        <svg viewBox="0 0 292 84" height="84" preserveAspectRatio="xMidYMid meet" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="WeldForge">
          <defs>
            <linearGradient id="shieldBody" x1="15%" y1="0%" x2="85%" y2="100%">
              <stop offset="0%"   stop-color="#1A2645"/>
              <stop offset="35%"  stop-color="#0B1226"/>
              <stop offset="70%"  stop-color="#060A18"/>
              <stop offset="100%" stop-color="#02050E"/>
            </linearGradient>
            <linearGradient id="shieldBevel" x1="50%" y1="0%" x2="50%" y2="100%">
              <stop offset="0%"   stop-color="#FFFFFF" stop-opacity="0.18"/>
              <stop offset="20%"  stop-color="#FFFFFF" stop-opacity="0.04"/>
              <stop offset="55%"  stop-color="#000000" stop-opacity="0"/>
              <stop offset="100%" stop-color="#000000" stop-opacity="0.55"/>
            </linearGradient>
            <radialGradient id="shieldGloss" cx="28%" cy="18%" r="55%">
              <stop offset="0%"   stop-color="#7AA8FF" stop-opacity="0.22"/>
              <stop offset="60%"  stop-color="#3D7EF5" stop-opacity="0.05"/>
              <stop offset="100%" stop-color="#3D7EF5" stop-opacity="0"/>
            </radialGradient>
            <radialGradient id="forgeInterior" cx="28" cy="41" r="34" gradientUnits="userSpaceOnUse">
              <stop offset="0%"   stop-color="#E8921F" stop-opacity="0.30"/>
              <stop offset="35%"  stop-color="#E8921F" stop-opacity="0.10"/>
              <stop offset="70%"  stop-color="#C06010" stop-opacity="0.04"/>
              <stop offset="100%" stop-color="#070C18"  stop-opacity="0"/>
            </radialGradient>
            <radialGradient id="weldPool" cx="50%" cy="30%" r="50%">
              <stop offset="0%"   stop-color="#FFD060" stop-opacity="0.6"/>
              <stop offset="50%"  stop-color="#E8921F" stop-opacity="0.3"/>
              <stop offset="100%" stop-color="#E8921F" stop-opacity="0"/>
            </radialGradient>
            <radialGradient id="sparkCore" cx="40%" cy="35%" r="60%">
              <stop offset="0%"   stop-color="#FFE8A0"/>
              <stop offset="45%"  stop-color="#FFAA30"/>
              <stop offset="100%" stop-color="#E8721F"/>
            </radialGradient>
            <clipPath id="plateClip">
              <path d="M 3 10 C 8 20 18 20 28 2 C 38 20 48 20 53 10 L 53 34 C 53 58 44 72 28 80 C 12 72 3 58 3 34 Z"/>
            </clipPath>
            <filter id="rayGlow" x="-50%" y="-50%" width="200%" height="200%">
              <feGaussianBlur stdDeviation="1.8" result="blur"/>
              <feMerge><feMergeNode in="blur"/><feMergeNode in="SourceGraphic"/></feMerge>
            </filter>
            <filter id="coreGlow" x="-80%" y="-80%" width="260%" height="260%">
              <feGaussianBlur stdDeviation="3.5" result="blur"/>
              <feMerge><feMergeNode in="blur"/><feMergeNode in="SourceGraphic"/></feMerge>
            </filter>
            <filter id="wGlow" x="-30%" y="-30%" width="160%" height="160%">
              <feGaussianBlur stdDeviation="1.2" result="blur"/>
              <feMerge><feMergeNode in="blur"/><feMergeNode in="SourceGraphic"/></feMerge>
            </filter>
          </defs>
          <path d="M 3 10 C 8 20 18 20 28 2 C 38 20 48 20 53 10 L 53 34 C 53 58 44 72 28 80 C 12 72 3 58 3 34 Z"
                fill="url(#shieldBody)" stroke="#3D7EF5" stroke-width="1.5" stroke-linejoin="round"/>
          <g clip-path="url(#plateClip)">
            <rect x="0" y="0" width="56" height="84" fill="url(#shieldBevel)"/>
            <rect x="0" y="0" width="56" height="84" fill="url(#shieldGloss)"/>
            <rect x="0" y="0" width="56" height="84" fill="url(#forgeInterior)"/>
          </g>
          <path d="M 6 14 C 11 22 19 22 28 6 C 37 22 45 22 50 14 L 50 34 C 50 56 42 69 28 75 C 14 69 6 56 6 34 Z"
                fill="none" stroke="#152040" stroke-width="0.75" stroke-linejoin="round"/>
          <polyline points="12.7,29.3 19.9,52.7 28,40 36.1,52.7 43.3,29.3"
                    fill="none" stroke="#B8CCEE" stroke-width="1.5"
                    stroke-linejoin="round" stroke-linecap="round"
                    filter="url(#wGlow)" clip-path="url(#plateClip)"/>
          <g clip-path="url(#plateClip)">
            <circle cx="28" cy="40" r="22" fill="none"
                    stroke="#E8921F" stroke-width="0.5" opacity="0.12"/>
            <circle cx="28" cy="40" r="16" fill="none"
                    stroke="#E8921F" stroke-width="0.8" opacity="0.22"/>
            <circle cx="28" cy="40" r="11"
                    fill="rgba(232,146,31,0.08)"
                    stroke="#E8921F" stroke-width="1" opacity="0.45"/>
            <ellipse cx="28" cy="50" rx="9" ry="4.5"
                     fill="url(#weldPool)" opacity="0.7"/>
            <line x1="28" y1="30" x2="28" y2="10"
                  stroke="#E8921F" stroke-width="2" stroke-linecap="round"
                  filter="url(#rayGlow)" opacity="0.9"/>
            <line x1="28" y1="50" x2="28" y2="74"
                  stroke="#E8921F" stroke-width="2" stroke-linecap="round"
                  filter="url(#rayGlow)" opacity="0.9"/>
            <line x1="19" y1="40" x2="5"  y2="40"
                  stroke="#E8921F" stroke-width="2" stroke-linecap="round"
                  filter="url(#rayGlow)" opacity="0.9"/>
            <line x1="37" y1="40" x2="51" y2="40"
                  stroke="#E8921F" stroke-width="2" stroke-linecap="round"
                  filter="url(#rayGlow)" opacity="0.9"/>
            <line x1="33.5" y1="34.5" x2="40" y2="28"
                  stroke="#E8921F" stroke-width="1.4" stroke-linecap="round"
                  filter="url(#rayGlow)" opacity="0.72"/>
            <line x1="22.5" y1="34.5" x2="16" y2="28"
                  stroke="#E8921F" stroke-width="1.4" stroke-linecap="round"
                  filter="url(#rayGlow)" opacity="0.72"/>
            <line x1="33.5" y1="45.5" x2="40" y2="52"
                  stroke="#E8921F" stroke-width="1.4" stroke-linecap="round"
                  filter="url(#rayGlow)" opacity="0.72"/>
            <line x1="22.5" y1="45.5" x2="16" y2="52"
                  stroke="#E8921F" stroke-width="1.4" stroke-linecap="round"
                  filter="url(#rayGlow)" opacity="0.72"/>
            <circle cx="28" cy="40" r="7.5"
                    fill="rgba(232,146,31,0.35)"
                    filter="url(#coreGlow)"/>
            <circle cx="28" cy="40" r="5.5"
                    fill="url(#sparkCore)"/>
            <circle cx="27" cy="39" r="2.2"
                    fill="#FFF0B0" opacity="0.9"/>
          </g>
          <text x="70" y="38" font-family="Syne, sans-serif" font-weight="700"
                font-size="18" fill="#9AAED0" letter-spacing="3.5">WELD</text>
          <text x="70" y="60" font-family="Syne, sans-serif" font-weight="800"
                font-size="18" fill="#F0E8D8" letter-spacing="3.5">FORGE</text>
          <line x1="70" y1="42.5" x2="205" y2="42.5" stroke="#1A2E5A" stroke-width="0.75"/>
          <circle cx="62" cy="36" r="2" fill="#3D7EF5"/>
          <circle cx="62" cy="58" r="2.5" fill="#E8921F" filter="url(#rayGlow)"/>
        </svg>
        """;
}
