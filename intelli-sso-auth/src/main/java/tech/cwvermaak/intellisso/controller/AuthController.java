package tech.cwvermaak.intellisso.controller;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;
import tech.cwvermaak.intellisso.config.tenant.TenantContext;
import tech.cwvermaak.intellisso.model.User;
import tech.cwvermaak.intellisso.model.dto.AuthResponseDto;
import tech.cwvermaak.intellisso.model.dto.LoginRequestDto;
import tech.cwvermaak.intellisso.model.dto.RegisterRequestDto;
import tech.cwvermaak.intellisso.model.dto.SamlProviderDto;
import tech.cwvermaak.intellisso.model.dto.SocialProviderDto;
import tech.cwvermaak.intellisso.model.dto.UserResponseDto;
import tech.cwvermaak.intellisso.repository.UserRepository;
import tech.cwvermaak.intellisso.service.AuthService;
import tech.cwvermaak.intellisso.service.EmailVerificationService;
import tech.cwvermaak.intellisso.service.PasswordResetService;
import tech.cwvermaak.intellisso.service.TenantSamlService;
import tech.cwvermaak.intellisso.service.TenantService;

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
        passwordResetService.requestReset(email);
        // Always 200 to avoid user enumeration.
        return ResponseEntity.ok(Map.of("message", "If that email is registered, a reset link has been sent."));
    }

    @PostMapping("/reset-password")
    public ResponseEntity<Map<String, String>> resetPassword(@RequestBody Map<String, String> body) {
        String token = body.get("token");
        String newPassword = body.get("newPassword");
        try {
            passwordResetService.resetPassword(token, newPassword);
            return ResponseEntity.ok(Map.of("message", "Password has been reset successfully."));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
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
