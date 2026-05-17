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

    @Transactional
    public void requestReset(String email) {
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
                .expiresAt(LocalDateTime.now().plusHours(EXPIRY_HOURS))
                .build();

        resetTokenRepository.save(resetToken);

        // Deliver the single-use token through the mail abstraction. The raw
        // token is never written to the application log — LoggingMailService
        // keeps the body (and therefore the token) at DEBUG only.
        mailService.send(user.getEmail(),
                "Reset your " + tenantLabel(tenant) + " password",
                buildResetEmailBody(tenant, rawToken));

        auditService.recordUserAction(AuditEventTypes.AUTH_PASSWORD_RESET_REQUESTED, user,
                AuditEventTypes.TARGET_USER, String.valueOf(user.getId()), null);
    }

    @Transactional
    public void resetPassword(String token, String newPassword) {
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
    }

    // ---- internals ---------------------------------------------------

    private static String tenantLabel(Tenant tenant) {
        return tenant.getDisplayName() != null && !tenant.getDisplayName().isBlank()
                ? tenant.getDisplayName() : tenant.getName();
    }

    private String buildResetEmailBody(Tenant tenant, String rawToken) {
        StringBuilder b = new StringBuilder();
        b.append("A password reset was requested for your ")
         .append(tenantLabel(tenant)).append(" account.\n\n");
        if (frontendBaseUrl != null && !frontendBaseUrl.isBlank()) {
            b.append("Reset your password here:\n")
             .append(frontendBaseUrl).append("/reset-password?tenant=")
             .append(tenant.getSlug()).append("&token=").append(rawToken).append("\n\n");
        } else {
            b.append("Use this reset token to set a new password:\n\n")
             .append(rawToken).append("\n\n");
        }
        b.append("This token expires in ").append(EXPIRY_HOURS)
         .append(" hour(s). If you did not request a reset, you can safely ignore this email.");
        return b.toString();
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
