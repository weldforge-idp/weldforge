package tech.cwvermaak.weldforge.service;

import jakarta.persistence.EntityNotFoundException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import tech.cwvermaak.weldforge.config.tenant.TenantContext;
import tech.cwvermaak.weldforge.model.PasswordResetToken;
import tech.cwvermaak.weldforge.model.Tenant;
import tech.cwvermaak.weldforge.model.User;
import tech.cwvermaak.weldforge.repository.PasswordResetTokenRepository;
import tech.cwvermaak.weldforge.repository.TenantRepository;
import tech.cwvermaak.weldforge.repository.UserRepository;
import tech.cwvermaak.weldforge.service.audit.AuditEventTypes;
import tech.cwvermaak.weldforge.service.audit.AuditService;
import tech.cwvermaak.weldforge.service.mail.MailService;
import tech.cwvermaak.weldforge.service.security.PasswordPolicyService;
import tech.cwvermaak.weldforge.service.security.RefreshTokenService;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.HexFormat;

@Service
@RequiredArgsConstructor
@Slf4j
public class PasswordResetService {

    private final UserRepository userRepository;
    private final TenantRepository tenantRepository;
    private final PasswordResetTokenRepository resetTokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final PasswordPolicyService passwordPolicyService;
    private final AuditService auditService;
    private final RefreshTokenService refreshTokenService;
    private final MailService mailService;

    /** Optional public base URL for the reset page; blank means the email carries the bare token. */
    @Value("${app.frontend.base-url:}")
    private String frontendBaseUrl;

    private static final int TOKEN_BYTE_LENGTH = 32;
    private static final int EXPIRY_HOURS = 1;

    /** Backwards-compatible entry point — a reset with no in-flow return target. */
    @Transactional
    public void requestReset(String email) {
        requestReset(email, null);
    }

    /**
     * Request a password reset.
     *
     * @param email    account email; a non-existent address succeeds silently
     *                 (no user enumeration)
     * @param returnTo optional base64url-encoded URL the user should land on
     *                 after the reset completes — the sign-in screen carrying
     *                 the original OIDC continuation. Honoured only when the
     *                 tenant has return-to-caller enabled and the decoded URL
     *                 is on the auth server's own origin; otherwise dropped.
     */
    @Transactional
    public void requestReset(String email, String returnTo) {
        Tenant tenant = currentTenant();

        // Per-tenant feature flag: when password recovery is disabled the
        // endpoint should look like it doesn't exist. 404 (via GlobalExceptionHandler)
        // is more honest than 200 here — the feature is off, not the user missing.
        if (Boolean.FALSE.equals(tenant.getPasswordRecoveryEnabled())) {
            throw new EntityNotFoundException("Password recovery is not available for this tenant");
        }

        User user = userRepository.findByTenantIdAndEmailIgnoreCase(tenant.getId(), email)
                .orElse(null);

        if (user == null) {
            // Silently succeed to avoid user enumeration.
            return;
        }

        // Cleanup any outstanding unused tokens for this user.
        resetTokenRepository.deleteByUserIdAndUsedFalse(user.getId());

        // Generate a cryptographically random token.
        String rawToken = generateToken();
        String tokenHash = sha256Hex(rawToken);

        PasswordResetToken resetToken = PasswordResetToken.builder()
                .tenant(tenant)
                .user(user)
                .tokenHash(tokenHash)
                .returnTo(resolveReturnTo(tenant, returnTo))
                .expiresAt(LocalDateTime.now().plusHours(EXPIRY_HOURS))
                .build();

        resetTokenRepository.save(resetToken);

        // Deliver the single-use token through the mail abstraction. The raw
        // token is never written to the application log — LoggingMailService
        // keeps the body (and therefore the token) at DEBUG only.
        String subject = "Reset your " + tenantLabel(tenant) + " password";
        String base = frontendBaseUrl == null ? "" : frontendBaseUrl.trim();
        if (base.isBlank()) {
            // No reset-page base URL configured — fall back to a bare-token email.
            mailService.send(user.getEmail(), subject, buildTokenEmail(tenant, rawToken));
        } else {
            String resetUrl = base + "/reset-password?tenant=" + tenant.getSlug()
                    + "&token=" + rawToken;
            mailService.send(user.getEmail(), subject,
                    buildResetTextBody(tenant, resetUrl),
                    buildResetHtmlBody(tenant, resetUrl));
        }

        auditService.recordUserAction(AuditEventTypes.AUTH_PASSWORD_RESET_REQUESTED, user,
                AuditEventTypes.TARGET_USER, String.valueOf(user.getId()), null);
    }

    /**
     * Complete a password reset.
     *
     * @return the validated, same-origin return target the SPA should send the
     *         user back to (the sign-in screen with the OIDC continuation), or
     *         null when there is none / the tenant has return-to-caller off.
     */
    @Transactional
    public String resetPassword(String token, String newPassword) {
        String tokenHash = sha256Hex(token);

        PasswordResetToken resetToken = resetTokenRepository.findByTokenHash(tokenHash)
                .orElseThrow(() -> new IllegalArgumentException("Invalid or expired reset token"));

        if (resetToken.isUsed()) {
            throw new IllegalArgumentException("Invalid or expired reset token");
        }

        if (resetToken.getExpiresAt().isBefore(LocalDateTime.now())) {
            throw new IllegalArgumentException("Invalid or expired reset token");
        }

        passwordPolicyService.validate(newPassword);

        User user = resetToken.getUser();
        user.setPassword(passwordEncoder.encode(newPassword));
        user.setTokenVersion(user.getTokenVersion() + 1);
        // A completed reset proves account ownership — clear any failed-login
        // lockout so the user is not locked out of the password they just set.
        user.setFailedLoginAttempts(0);
        user.setLockedUntil(null);
        userRepository.save(user);

        resetToken.setUsed(true);
        resetTokenRepository.save(resetToken);

        // A reset is the canonical account-recovery action: terminate every
        // existing session so a token thief is locked out. The token_version
        // bump above invalidates outstanding access tokens; this revokes the
        // refresh-token side, which token_version does not cover.
        int revoked = refreshTokenService.revokeAllForUser(user, "password_reset");

        auditService.recordUserAction(AuditEventTypes.AUTH_PASSWORD_RESET_COMPLETED, user,
                AuditEventTypes.TARGET_USER, String.valueOf(user.getId()),
                AuditService.meta("refresh_tokens_revoked", revoked));

        // Return target for the SPA. It was already same-origin validated when
        // the token was minted; re-check the tenant flag so an operator who
        // turns return-to-caller off mid-flight is honoured.
        return Boolean.TRUE.equals(resetToken.getTenant().getReturnToCallerEnabled())
                ? resetToken.getReturnTo()
                : null;
    }

    // ---- internals ---------------------------------------------------

    private static String tenantLabel(Tenant tenant) {
        return tenant.getDisplayName() != null && !tenant.getDisplayName().isBlank()
                ? tenant.getDisplayName() : tenant.getName();
    }

    /** Plain-text body — also the fallback part of the multipart message. */
    private String buildResetTextBody(Tenant tenant, String resetUrl) {
        return "A password reset was requested for your " + tenantLabel(tenant) + " account.\n\n"
             + "Reset your password:\n" + resetUrl + "\n\n"
             + "This link expires in " + EXPIRY_HOURS + " hour(s). "
             + "If you did not request a reset, you can safely ignore this email.";
    }

    /** Bare-token email — fallback when no reset-page base URL is configured. */
    private String buildTokenEmail(Tenant tenant, String rawToken) {
        return "A password reset was requested for your " + tenantLabel(tenant) + " account.\n\n"
             + "Use this reset token to set a new password:\n\n" + rawToken + "\n\n"
             + "This token expires in " + EXPIRY_HOURS + " hour(s). "
             + "If you did not request a reset, you can safely ignore this email.";
    }

    /** HTML body — a branded "Reset password" button with the URL shown as a fallback. */
    private String buildResetHtmlBody(Tenant tenant, String resetUrl) {
        String html = """
            <!doctype html>
            <html><body style="margin:0;padding:0;background:#f3f4f6;">
            <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#f3f4f6;">
            <tr><td align="center" style="padding:32px 16px;">
            <table role="presentation" cellpadding="0" cellspacing="0" style="width:468px;max-width:468px;background:#ffffff;border:1px solid #e5e7eb;border-radius:8px;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;">
            <tr><td style="padding:32px;">
            <h1 style="margin:0 0 16px;font-size:20px;color:#111827;">Reset your __LABEL__ password</h1>
            <p style="margin:0 0 24px;font-size:14px;line-height:1.6;color:#374151;">A password reset was requested for your account. Click the button below to choose a new password.</p>
            <table role="presentation" cellpadding="0" cellspacing="0"><tr><td style="border-radius:6px;background:__COLOR__;">
            <a href="__URL__" style="display:inline-block;padding:12px 32px;font-size:14px;font-weight:600;color:#ffffff;text-decoration:none;">Reset password</a>
            </td></tr></table>
            <p style="margin:24px 0 4px;font-size:12px;color:#6b7280;">Or paste this link into your browser:</p>
            <p style="margin:0;font-size:12px;word-break:break-all;"><a href="__URL__" style="color:__COLOR__;">__URL__</a></p>
            <p style="margin:24px 0 0;font-size:12px;color:#9ca3af;">This link expires in __HRS__ hour(s). If you did not request a reset, you can safely ignore this email.</p>
            </td></tr></table>
            </td></tr></table>
            </body></html>
            """;
        return html
                .replace("__LABEL__", escapeHtml(tenantLabel(tenant)))
                .replace("__COLOR__", buttonColor(tenant))
                .replace("__URL__", escapeHtml(resetUrl))
                .replace("__HRS__", String.valueOf(EXPIRY_HOURS));
    }

    /** Tenant primaryColor when it is a valid hex colour, else a neutral default. */
    private static String buttonColor(Tenant tenant) {
        Object pc = tenant.getBranding() != null ? tenant.getBranding().get("primaryColor") : null;
        if (pc instanceof String s && s.matches("#[0-9A-Fa-f]{3,8}")) {
            return s;
        }
        return "#2D5FA8";
    }

    private static String escapeHtml(String s) {
        if (s == null) return "";
        return s.replace("&", "&amp;").replace("<", "&lt;")
                .replace(">", "&gt;").replace("\"", "&quot;");
    }

    private Tenant currentTenant() {
        String slug = TenantContext.get();
        if (slug == null || slug.isBlank()) {
            throw new IllegalStateException("No tenant in request context");
        }
        return tenantRepository.findBySlug(slug)
                .orElseThrow(() -> new EntityNotFoundException("Unknown tenant: " + slug));
    }

    /**
     * Validate an optional return-to URL supplied at forgot-password time.
     * It is kept only when the tenant has return-to-caller enabled and the
     * base64url-decoded target sits on the auth server's own origin — a reset
     * link must never be coercible into an open redirect. Anything malformed,
     * cross-origin, or arriving for a tenant with the feature off is dropped
     * (null), and the reset simply ends on the standalone confirmation screen.
     */
    private String resolveReturnTo(Tenant tenant, String returnTo) {
        if (returnTo == null || returnTo.isBlank()) return null;
        if (!Boolean.TRUE.equals(tenant.getReturnToCallerEnabled())) return null;
        String base = frontendBaseUrl == null ? "" : frontendBaseUrl.trim();
        if (base.isBlank()) return null;
        try {
            String decoded = new String(
                    Base64.getUrlDecoder().decode(returnTo.trim()), StandardCharsets.UTF_8);
            if (sameOrigin(URI.create(decoded), URI.create(base))) {
                return returnTo.trim();
            }
            log.warn("Dropped cross-origin password-reset returnTo for tenant {}", tenant.getSlug());
        } catch (RuntimeException e) {
            log.warn("Dropped malformed password-reset returnTo for tenant {}", tenant.getSlug());
        }
        return null;
    }

    /** Scheme + host + (default-aware) port equality. */
    private static boolean sameOrigin(URI a, URI b) {
        return a.getScheme() != null && a.getScheme().equalsIgnoreCase(b.getScheme())
                && a.getHost() != null && a.getHost().equalsIgnoreCase(b.getHost())
                && effectivePort(a) == effectivePort(b);
    }

    private static int effectivePort(URI u) {
        if (u.getPort() != -1) return u.getPort();
        return "https".equalsIgnoreCase(u.getScheme()) ? 443 : 80;
    }

    /**
     * Persist a reset token tied to a freshly-created (invited) user.
     * Used by the admin-invite path so we can return the raw token to
     * the caller (regular {@link #requestReset} only logs it).
     */
    @Transactional
    public PasswordResetToken persistInviteToken(User user, String rawToken) {
        // Any outstanding unused tokens for this user should be wiped —
        // the freshly-issued one is authoritative.
        resetTokenRepository.deleteByUserIdAndUsedFalse(user.getId());
        PasswordResetToken token = PasswordResetToken.builder()
                .tenant(user.getTenant())
                .user(user)
                .tokenHash(sha256Hex(rawToken))
                // Invitation links can sit in an inbox a while — give them
                // a longer life than a self-service reset.
                .expiresAt(LocalDateTime.now().plusDays(7))
                .build();
        return resetTokenRepository.save(token);
    }

    /**
     * Admin-initiated, out-of-band password reset for an existing user — the
     * account-recovery path when email delivery is unavailable. Wipes any
     * pending tokens, mints a fresh single-use one (24h), and returns the raw
     * value so the admin can hand it to the user over a secure channel.
     */
    @Transactional
    public IssuedReset adminIssueReset(User user) {
        resetTokenRepository.deleteByUserIdAndUsedFalse(user.getId());
        String rawToken = generateToken();
        LocalDateTime expiresAt = LocalDateTime.now().plusHours(24);
        resetTokenRepository.save(PasswordResetToken.builder()
                .tenant(user.getTenant())
                .user(user)
                .tokenHash(sha256Hex(rawToken))
                .expiresAt(expiresAt)
                .build());
        auditService.recordUserAction(AuditEventTypes.AUTH_PASSWORD_RESET_REQUESTED, user,
                AuditEventTypes.TARGET_USER, String.valueOf(user.getId()),
                AuditService.meta("channel", "admin_out_of_band"));
        return new IssuedReset(rawToken, expiresAt);
    }

    /** Result of an admin-issued reset — the raw token and its expiry. */
    public record IssuedReset(String rawToken, LocalDateTime expiresAt) {}

    public static String generateToken() {
        byte[] bytes = new byte[TOKEN_BYTE_LENGTH];
        new SecureRandom().nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    public static String sha256Hex(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(input.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }
}
