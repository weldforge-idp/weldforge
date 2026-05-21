package tech.cwvermaak.weldforge.controller;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;
import tech.cwvermaak.weldforge.config.tenant.TenantContext;
import tech.cwvermaak.weldforge.model.User;
import tech.cwvermaak.weldforge.model.dto.AuthResponseDto;
import tech.cwvermaak.weldforge.model.dto.LoginRequestDto;
import tech.cwvermaak.weldforge.model.dto.RegisterRequestDto;
import tech.cwvermaak.weldforge.model.dto.SamlProviderDto;
import tech.cwvermaak.weldforge.model.dto.SocialProviderDto;
import tech.cwvermaak.weldforge.model.dto.TenantBrandingDto;
import tech.cwvermaak.weldforge.model.dto.UserResponseDto;
import tech.cwvermaak.weldforge.repository.UserRepository;
import tech.cwvermaak.weldforge.service.AuthService;
import tech.cwvermaak.weldforge.service.EmailVerificationService;
import tech.cwvermaak.weldforge.service.PasswordResetService;
import tech.cwvermaak.weldforge.service.TenantSamlService;
import tech.cwvermaak.weldforge.service.TenantService;
import tech.cwvermaak.weldforge.service.TenantVerificationService;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;
    private final EmailVerificationService emailVerificationService;
    private final PasswordResetService passwordResetService;
    private final UserRepository userRepository;
    private final TenantService tenantService;
    private final TenantSamlService tenantSamlService;
    private final TenantVerificationService tenantVerificationService;

    @PostMapping("/register")
    public ResponseEntity<AuthResponseDto> register(@RequestBody RegisterRequestDto request,
                                                    HttpServletRequest httpRequest,
                                                    HttpServletResponse response) {
        return ResponseEntity.ok(authService.register(request, httpRequest, response));
    }

    @PostMapping("/login")
    public ResponseEntity<AuthResponseDto> login(@RequestBody LoginRequestDto request,
                                                 HttpServletRequest httpRequest,
                                                 HttpServletResponse response) {
        return ResponseEntity.ok(authService.login(request, httpRequest, response));
    }

    /**
     * Exchange the refresh cookie for a fresh access token. Rotating: the
     * caller's current refresh token is invalidated and a successor is
     * written into the cookie. Reusing an already-rotated token revokes
     * the whole family and is treated as a theft signal.
     */
    @PostMapping("/refresh")
    public ResponseEntity<AuthResponseDto> refresh(HttpServletRequest request, HttpServletResponse response) {
        return ResponseEntity.ok(authService.refresh(request, response));
    }

    /**
     * Revoke every session for the caller — all refresh tokens are killed
     * and the token_version is bumped so every outstanding access token
     * stops authenticating immediately.
     */
    @PostMapping("/logout-all")
    public ResponseEntity<Map<String, Object>> logoutAll(@AuthenticationPrincipal String email) {
        String tenantSlug = TenantContext.get();
        User user = userRepository.findByTenant_SlugAndEmailIgnoreCase(tenantSlug, email)
                .orElseThrow(() -> new RuntimeException("User not found"));
        int revoked = authService.logoutAll(user);
        return ResponseEntity.ok(Map.of("refreshTokensRevoked", revoked));
    }

    @GetMapping("/me")
    public ResponseEntity<UserResponseDto> currentUser(@AuthenticationPrincipal String email) {
        String tenantSlug = TenantContext.get();
        User user = userRepository.findByTenant_SlugAndEmailIgnoreCase(tenantSlug, email)
                .orElseThrow(() -> new RuntimeException("User not found"));

        return ResponseEntity.ok(UserResponseDto.builder()
                .id(user.getId())
                .name(user.getName())
                .email(user.getEmail())
                .imageUrl(user.getImageUrl())
                .provider(user.getProvider())
                .role(user.getRole() != null ? user.getRole().getName() : null)
                .build());
    }

    @PutMapping("/me")
    public ResponseEntity<UserResponseDto> updateMe(@AuthenticationPrincipal String email,
                                                     @RequestBody Map<String, String> body) {
        if (email == null || email.isBlank() || "anonymousUser".equals(email)) {
            return ResponseEntity.status(401).build();
        }
        try {
            User user = authService.updateMe(email,
                    body.get("name"), body.get("email"), body.get("cellPhoneNumber"));
            return ResponseEntity.ok(UserResponseDto.builder()
                    .id(user.getId())
                    .name(user.getName())
                    .email(user.getEmail())
                    .imageUrl(user.getImageUrl())
                    .provider(user.getProvider())
                    .role(user.getRole() != null ? user.getRole().getName() : null)
                    .build());
        } catch (IllegalArgumentException e) {
            return ResponseEntity.status(400)
                    .body(UserResponseDto.builder().email(e.getMessage()).build());
        }
    }

    @PostMapping("/change-password")
    public ResponseEntity<Map<String, String>> changePassword(@AuthenticationPrincipal String email,
                                                               @RequestBody Map<String, String> body) {
        if (email == null || email.isBlank() || "anonymousUser".equals(email)) {
            return ResponseEntity.status(401).body(Map.of("error", "Not signed in"));
        }
        String current = body.get("currentPassword");
        String next = body.get("newPassword");
        if (current == null || next == null) {
            return ResponseEntity.badRequest().body(Map.of(
                    "error", "currentPassword and newPassword are required"));
        }
        try {
            authService.changePassword(email, current, next);
            return ResponseEntity.ok(Map.of("message", "Password changed."));
        } catch (org.springframework.security.authentication.BadCredentialsException e) {
            return ResponseEntity.status(401).body(Map.of("error", e.getMessage()));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    @PostMapping("/verify-email")
    public ResponseEntity<Map<String, String>> verifyEmail(@RequestBody Map<String, String> body) {
        String token = body.get("token");
        try {
            emailVerificationService.verify(token);
            return ResponseEntity.ok(Map.of("message", "Email verified successfully."));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    @PostMapping("/resend-verification")
    public ResponseEntity<Map<String, String>> resendVerification(@RequestBody Map<String, String> body) {
        String email = body.get("email");
        emailVerificationService.resendVerification(email);
        // Always 200 to avoid user enumeration.
        return ResponseEntity.ok(Map.of("message", "If that email is registered and unverified, a verification link has been sent."));
    }

    @PostMapping("/forgot-password")
    public ResponseEntity<Map<String, String>> forgotPassword(@RequestBody Map<String, String> body) {
        String email = body.get("email");
        // returnTo: optional base64url URL the SPA forwards from the login
        // page's OIDC continuation — validated and stored server-side.
        passwordResetService.requestReset(email, body.get("returnTo"));
        // Always 200 to avoid user enumeration.
        return ResponseEntity.ok(Map.of("message", "If that email is registered, a reset link has been sent."));
    }

    @PostMapping("/reset-password")
    public ResponseEntity<Map<String, String>> resetPassword(@RequestBody Map<String, String> body) {
        String token = body.get("token");
        String newPassword = body.get("newPassword");
        try {
            String returnTo = passwordResetService.resetPassword(token, newPassword);
            Map<String, String> resp = new HashMap<>();
            resp.put("message", "Password has been reset successfully.");
            // Present only when the reset began inside an app flow — the SPA
            // sends the user back to the sign-in screen with this continuation.
            if (returnTo != null) resp.put("returnTo", returnTo);
            return ResponseEntity.ok(resp);
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    @GetMapping("/tenants/{slug}/branding")
    public ResponseEntity<TenantBrandingDto> tenantBranding(@PathVariable String slug) {
        return ResponseEntity.ok(tenantService.getBrandingForSlug(slug));
    }

    @GetMapping("/tenants/{slug}/social-providers")
    public ResponseEntity<List<SocialProviderDto>> tenantSocialProviders(@PathVariable String slug) {
        return ResponseEntity.ok(tenantService.listEnabledProvidersForSlug(slug));
    }

    @GetMapping("/tenants/{slug}/saml-providers")
    public ResponseEntity<List<SamlProviderDto>> tenantSamlProviders(@PathVariable String slug) {
        return ResponseEntity.ok(tenantSamlService.listEnabledForSlug(slug));
    }

    /**
     * Click-through landing page for the emailed verification link.
     * Renders a self-contained HTML page with a single "Confirm" button
     * whose inline JS POSTs to {@link #verifyContact(String)}. The GET
     * is deliberately non-destructive: email-prefetch and safe-link
     * scanners can resolve the URL without consuming the token, leaving
     * the actual flip behind an explicit user click.
     *
     * <p>Cache-Control: no-store keeps a corporate proxy from caching
     * the token-bearing URL.</p>
     */
    @GetMapping(value = "/tenants/verify-contact-page",
                produces = org.springframework.http.MediaType.TEXT_HTML_VALUE)
    public ResponseEntity<String> verifyContactPage(@RequestParam("token") String token) {
        String safeToken = htmlEscape(token);
        String html = """
            <!doctype html><html lang="en"><head>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width,initial-scale=1">
            <title>Verify tenant ownership — WeldForge</title>
            <style>
              body { font-family: system-ui, -apple-system, 'Segoe UI', sans-serif;
                     background: #0b1020; color: #e6ebf5;
                     display: flex; align-items: center; justify-content: center;
                     min-height: 100vh; margin: 0; }
              .card { background: #141a30; border: 1px solid #2a3354;
                      border-radius: 10px; padding: 32px 28px;
                      max-width: 420px; box-shadow: 0 18px 48px rgba(0,0,0,.55); }
              h1 { font-size: 20px; margin: 0 0 12px; }
              p  { font-size: 14px; line-height: 1.5; color: #c8d0e0; margin: 0 0 18px; }
              button { background: #4A8FF5; color: #fff; border: 0;
                       padding: 12px 20px; border-radius: 6px;
                       font: inherit; font-size: 14px; font-weight: 600;
                       cursor: pointer; width: 100%; }
              button:hover { background: #5e9eff; }
              button:disabled { opacity: 0.5; cursor: progress; }
              .msg { margin-top: 16px; font-size: 13px; }
              .ok  { color: #6ad19c; }
              .err { color: #ff8d8d; }
              code { background: rgba(0,0,0,.25); padding: 1px 5px;
                     border-radius: 3px; font-size: 12px; }
            </style></head><body>
            <div class="card">
              <h1>Confirm tenant ownership</h1>
              <p>Click below to confirm that you control the contact email for this WeldForge tenant.
                 This link can be used once and expires after 48 hours.</p>
              <button id="go" type="button">Confirm verification</button>
              <div class="msg" id="msg"></div>
            </div>
            <script>
              const token = %s;
              const btn = document.getElementById('go');
              const msg = document.getElementById('msg');
              btn.addEventListener('click', async () => {
                btn.disabled = true;
                msg.textContent = '';
                msg.className = 'msg';
                try {
                  const r = await fetch('/api/auth/tenants/verify-contact?token=' + encodeURIComponent(token), {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: '{}'
                  });
                  const data = await r.json();
                  if (r.ok) {
                    msg.textContent = 'Verified — ' + (data.displayName || data.slug) + ' is now marked verified.';
                    msg.className = 'msg ok';
                    btn.style.display = 'none';
                  } else {
                    msg.textContent = 'Could not verify: ' + (data.message || 'invalid or expired token');
                    msg.className = 'msg err';
                    btn.disabled = false;
                  }
                } catch (e) {
                  msg.textContent = 'Network error — retry?';
                  msg.className = 'msg err';
                  btn.disabled = false;
                }
              });
            </script>
            </body></html>
            """.formatted("\"" + safeToken + "\"");
        return ResponseEntity.ok()
                .header("Cache-Control", "no-store")
                .header("X-Robots-Tag", "noindex, nofollow")
                .header(org.springframework.http.HttpHeaders.CONTENT_TYPE,
                        "text/html; charset=UTF-8")
                .body(html);
    }

    private static String htmlEscape(String s) {
        if (s == null) return "";
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                .replace("\"", "&quot;").replace("'", "&#39;");
    }

    /**
     * Consume an emailed tenant-verification token. Unauthenticated by
     * design: whoever can read the contact_email inbox holds the
     * proof. On success the tenant's verified bit flips and the
     * response carries the slug + display name so the SPA can render a
     * success page. See docs/auth-url-spec.md §"Tenant identity-proofing".
     */
    @PostMapping("/tenants/verify-contact")
    public ResponseEntity<?> verifyContact(@RequestParam("token") String token) {
        try {
            TenantVerificationService.VerificationResult result =
                    tenantVerificationService.consumeToken(token);
            return ResponseEntity.ok(Map.of(
                    "slug",        result.slug(),
                    "displayName", result.displayName(),
                    "verified",    true));
        } catch (IllegalArgumentException e) {
            // Same vague error for unknown / expired / used — never tell
            // the caller WHY the token failed, otherwise it becomes an
            // oracle for token-state probing.
            return ResponseEntity.badRequest().body(Map.of(
                    "error",   "invalid_or_expired_token",
                    "message", e.getMessage()));
        }
    }
}
