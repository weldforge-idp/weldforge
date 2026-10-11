package tech.cwvermaak.weldforge.service;

import jakarta.persistence.EntityNotFoundException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import tech.cwvermaak.weldforge.config.tenant.PublicHostProperties;
import tech.cwvermaak.weldforge.model.EmailVerificationToken;
import tech.cwvermaak.weldforge.model.Tenant;
import tech.cwvermaak.weldforge.model.User;
import tech.cwvermaak.weldforge.repository.EmailVerificationTokenRepository;
import tech.cwvermaak.weldforge.repository.TenantRepository;
import tech.cwvermaak.weldforge.repository.UserRepository;
import tech.cwvermaak.weldforge.service.audit.AuditEventTypes;
import tech.cwvermaak.weldforge.service.audit.AuditService;
import tech.cwvermaak.weldforge.service.mail.ActionEmail;
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
     * Declared last on purpose: @RequiredArgsConstructor builds the constructor
     * in field order, and the BDD steps construct this service positionally.
     */
    private final PublicHostProperties publicHost;

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
        Tenant tenant = user.getTenant();
        String subject = "Verify your " + tenantLabel(tenant) + " email address";
        String origin = publicHost.originForTenant(tenant.getSlug());

        if (origin == null || origin.isBlank()) {
            // No public-host config (a self-host that has not set one) — the
            // bare token is all we can offer, and the mail says where it goes.
            mailService.send(user.getEmail(), subject, buildTokenEmail(tenant, rawToken));
        } else {
            // The tenant's own subdomain, matching the host the person signed
            // up on, so the link does not look like it belongs to someone
            // else. The token is base64url (no padding), so it needs no
            // percent-encoding to survive a query string.
            String verifyUrl = origin + "/verify-email?token=" + rawToken;
            mailService.send(user.getEmail(), subject,
                    buildVerifyTextBody(tenant, verifyUrl),
                    buildVerifyHtmlBody(tenant, verifyUrl));
        }

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
        // The tenant the request names, not a leftover session cookie's (B-TEN-7).
        String slug = tech.cwvermaak.weldforge.config.tenant.TenantResolverFilter.requestedTenantOrContext();
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

    // ---- mail bodies -------------------------------------------------

    private static String tenantLabel(Tenant tenant) {
        return tenant.getDisplayName() != null && !tenant.getDisplayName().isBlank()
                ? tenant.getDisplayName() : tenant.getName();
    }

    private static String intro(Tenant tenant) {
        return "Confirm your email address to finish setting up your "
                + tenantLabel(tenant) + " account.";
    }

    private static String footer() {
        return "This link expires in " + EXPIRY_HOURS + " hours. "
                + "If you did not create this account, you can ignore this email.";
    }

    private static String buildVerifyTextBody(Tenant tenant, String verifyUrl) {
        return ActionEmail.text(intro(tenant), "Verify your email address:", verifyUrl, footer());
    }

    private static String buildVerifyHtmlBody(Tenant tenant, String verifyUrl) {
        return ActionEmail.html(
                "Verify your " + tenantLabel(tenant) + " email address",
                intro(tenant),
                "Verify email address",
                verifyUrl,
                ActionEmail.buttonColor(tenant.getBranding()),
                footer());
    }

    /** No public host configured — the token alone, with somewhere to put it. */
    private static String buildTokenEmail(Tenant tenant, String rawToken) {
        return intro(tenant) + "\n\n"
                + "Enter this verification token on the email-verification page:\n\n"
                + rawToken + "\n\n"
                + "This token expires in " + EXPIRY_HOURS + " hours. "
                + "If you did not create this account, you can ignore this email.";
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
