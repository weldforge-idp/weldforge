package tech.cwvermaak.intellisso.service;

import jakarta.persistence.EntityNotFoundException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import tech.cwvermaak.intellisso.config.tenant.TenantContext;
import tech.cwvermaak.intellisso.model.PasswordResetToken;
import tech.cwvermaak.intellisso.model.Tenant;
import tech.cwvermaak.intellisso.model.User;
import tech.cwvermaak.intellisso.repository.PasswordResetTokenRepository;
import tech.cwvermaak.intellisso.repository.TenantRepository;
import tech.cwvermaak.intellisso.repository.UserRepository;
import tech.cwvermaak.intellisso.service.audit.AuditEventTypes;
import tech.cwvermaak.intellisso.service.audit.AuditService;
import tech.cwvermaak.intellisso.service.security.PasswordPolicyService;

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

    private static final int TOKEN_BYTE_LENGTH = 32;
    private static final int EXPIRY_HOURS = 1;

    @Transactional
    public void requestReset(String email) {
        Tenant tenant = currentTenant();

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

        // In production this would be emailed. For now, log it.
        log.info("Password reset token for {}: {}", email, rawToken);

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

        auditService.recordUserAction(AuditEventTypes.AUTH_PASSWORD_RESET_COMPLETED, user,
                AuditEventTypes.TARGET_USER, String.valueOf(user.getId()), null);
    }

    // ---- internals ---------------------------------------------------

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
