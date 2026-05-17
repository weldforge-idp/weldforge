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
}
