package tech.cwvermaak.weldforge.service;

import jakarta.persistence.EntityNotFoundException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import tech.cwvermaak.weldforge.config.tenant.TenantContext;
import tech.cwvermaak.weldforge.model.EmailVerificationToken;
import tech.cwvermaak.weldforge.model.User;
import tech.cwvermaak.weldforge.repository.EmailVerificationTokenRepository;
import tech.cwvermaak.weldforge.repository.TenantRepository;
import tech.cwvermaak.weldforge.repository.UserRepository;
import tech.cwvermaak.weldforge.service.audit.AuditEventTypes;
import tech.cwvermaak.weldforge.service.audit.AuditService;
import tech.cwvermaak.weldforge.service.mail.MailService;

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
public class EmailVerificationService {

    private static final int TOKEN_BYTES = 32;
    private static final int EXPIRY_HOURS = 24;

    private final EmailVerificationTokenRepository tokenRepository;
    private final UserRepository userRepository;
    private final TenantRepository tenantRepository;
    private final AuditService auditService;
    private final MailService mailService;

    /**
     * Generate a verification token for the given user, hash it with SHA-256,
     * persist the hash, and email the raw token to the user via
     * {@link MailService}. The raw token is also returned for callers that
     * need it directly (e.g. tests).
     */
    @Transactional
    public String sendVerification(User user) {
        String rawToken = generateRandomToken();
        String hash = sha256Hex(rawToken);

        EmailVerificationToken token = EmailVerificationToken.builder()
                .tenant(user.getTenant())
                .user(user)
                .tokenHash(hash)
                .expiresAt(LocalDateTime.now().plusHours(EXPIRY_HOURS))
                .build();

        tokenRepository.save(token);

        // Routed through the mail abstraction — the raw token is not logged
        // at INFO. See LoggingMailService for the log-level rationale.
        mailService.send(user.getEmail(),
                "Verify your WeldForge email address",
                "Confirm your email address with this verification token:\n\n"
                        + rawToken + "\n\nThis token expires in " + EXPIRY_HOURS + " hours. "
                        + "If you did not create this account, you can ignore this email.");

        auditService.recordUserAction(AuditEventTypes.AUTH_EMAIL_VERIFICATION_SENT, user,
                AuditEventTypes.TARGET_USER, String.valueOf(user.getId()), null);

        return rawToken;
    }

    /**
     * Verify the raw token: look up its SHA-256 hash, validate not expired
     * or used, then mark the user as email-verified and the token as used.
     */
    @Transactional
    public void verify(String rawToken) {
        String hash = sha256Hex(rawToken);

        EmailVerificationToken token = tokenRepository.findByTokenHash(hash)
                .orElseThrow(() -> new IllegalArgumentException("Invalid verification token"));

        if (token.getUsed()) {
            throw new IllegalArgumentException("Verification token already used");
        }
        if (token.getExpiresAt().isBefore(LocalDateTime.now())) {
            throw new IllegalArgumentException("Verification token has expired");
        }

        User user = token.getUser();
        user.setEmailVerified(true);
        userRepository.save(user);

        token.setUsed(true);
        tokenRepository.save(token);

        auditService.recordUserAction(AuditEventTypes.AUTH_EMAIL_VERIFIED, user,
                AuditEventTypes.TARGET_USER, String.valueOf(user.getId()), null);
    }

    /**
     * Resend verification for the given email. If the user is not found or is
     * already verified, this method silently returns to prevent user enumeration.
     */
    @Transactional
    public void resendVerification(String email) {
        String slug = TenantContext.get();
        if (slug == null || slug.isBlank()) return;

        var tenantOpt = tenantRepository.findBySlug(slug);
        if (tenantOpt.isEmpty()) return;

        var userOpt = userRepository.findByTenantIdAndEmailIgnoreCase(tenantOpt.get().getId(), email);
        if (userOpt.isEmpty()) return;

        User user = userOpt.get();
        if (user.isEmailVerified()) return;

        tokenRepository.deleteByUserIdAndUsedFalse(user.getId());
        sendVerification(user);
    }

    // ---- internals ---------------------------------------------------

    private static String generateRandomToken() {
        byte[] bytes = new byte[TOKEN_BYTES];
        new SecureRandom().nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    static String sha256Hex(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(input.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }
}
