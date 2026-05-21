package tech.cwvermaak.weldforge.service;

import jakarta.persistence.EntityNotFoundException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import tech.cwvermaak.weldforge.config.tenant.PublicHostProperties;
import tech.cwvermaak.weldforge.config.tenant.TenantAccessor;
import tech.cwvermaak.weldforge.model.Tenant;
import tech.cwvermaak.weldforge.model.TenantVerificationToken;
import tech.cwvermaak.weldforge.model.User;
import tech.cwvermaak.weldforge.repository.TenantRepository;
import tech.cwvermaak.weldforge.repository.TenantVerificationTokenRepository;
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

/**
 * Email-based identity-proofing challenge — V2a of tenant verification.
 *
 * <p>An admin (TENANT_ADMIN of the target tenant, or SUPER_ADMIN)
 * initiates a challenge for a tenant via
 * {@link #requestVerification(Long)}: a one-time token is minted,
 * stored as a SHA-256 hash, and the raw token is emailed (as a
 * clickable verification URL) to the tenant's {@code contact_email}.
 * Whoever can read that inbox can complete the proof via
 * {@link #consumeToken(String)}, which flips the tenant's
 * {@code verified_at} timestamp.</p>
 *
 * <p>This intentionally does <b>not</b> gate on the contact_email's
 * domain matching the tenant's OIDC {@code webOrigins} — that is
 * tracked as V2b. Today a malicious operator can still claim a free
 * gmail as their contact_email; the V1 super-admin-managed bit
 * (PR #36) remains the stronger control. V2a moves the trust anchor
 * from "super-admin says so" to "someone reachable at the claimed
 * email says so".</p>
 *
 * <p>See {@code docs/auth-url-spec.md} §"Tenant identity-proofing".</p>
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class TenantVerificationService {

    private static final int TOKEN_BYTES   = 32;
    private static final int EXPIRY_HOURS  = 48;

    private final TenantAccessor tenantAccessor;
    private final TenantRepository tenantRepository;
    private final UserRepository userRepository;
    private final TenantVerificationTokenRepository tokenRepository;
    private final AuditService auditService;
    private final MailService mailService;
    private final PublicHostProperties publicHost;

    /**
     * Path on the apex host that the email link points at. The default
     * lands on the backend HTML confirmation page (POST is the actual
     * state-changing endpoint; the GET click-through page guards against
     * email-prefetch / safe-link scanners consuming the token without
     * the user's explicit action). Operators with their own SPA page
     * can override this to e.g. {@code /verify-tenant}.
     */
    @Value("${wf.public.verify-contact-path:/api/auth/tenants/verify-contact-page}")
    private String verifyContactPath;

    /**
     * Issue a verification challenge for the given tenant. Requires the
     * caller to be at least TENANT_ADMIN of that tenant (SUPER_ADMIN
     * for any tenant). Invalidates any already-pending challenge for the
     * same tenant before issuing the new one — at most one live token
     * per tenant at any time. The raw token is emailed; the SHA-256
     * hash is persisted.
     *
     * @throws EntityNotFoundException tenant not found
     * @throws IllegalStateException   tenant has no contact_email
     */
    @Transactional
    public void requestVerification(Long tenantId) {
        Tenant tenant = tenantRepository.findById(tenantId)
                .orElseThrow(() -> new EntityNotFoundException("Tenant " + tenantId + " not found"));
        // TENANT_ADMIN scoped to the target tenant, or SUPER_ADMIN globally.
        // requireSameTenant against the target tenant's id; super-admin
        // is exempt by TenantAccessor's contract.
        tenantAccessor.requireTenantAdmin();
        tenantAccessor.requireSameTenant(tenant.getId());

        String contactEmail = tenant.getContactEmail();
        if (contactEmail == null || contactEmail.isBlank()) {
            throw new IllegalStateException(
                "Tenant " + tenant.getSlug() + " has no contact_email — set one first via PUT /api/admin/tenants/" + tenantId);
        }

        // One live token per tenant. A fresh challenge cancels any
        // previously-issued but not-yet-consumed token, even if the
        // contact_email changed in between.
        int invalidated = tokenRepository.invalidatePendingForTenant(tenant.getId(), LocalDateTime.now());

        String rawToken = generateRandomToken();
        TenantVerificationToken row = TenantVerificationToken.builder()
                .tenant(tenant)
                .tokenHash(sha256Hex(rawToken))
                .contactEmail(contactEmail.trim())
                .expiresAt(LocalDateTime.now().plusHours(EXPIRY_HOURS))
                .createdByUserId(currentActorId())
                .build();
        tokenRepository.save(row);

        String verifyUrl = publicHost.originForTenant(null)
                + verifyContactPath + "?token=" + rawToken;
        mailService.send(contactEmail.trim(),
                "Verify ownership of " + tenantLabel(tenant) + " on WeldForge",
                buildEmailBody(tenant, verifyUrl));

        auditService.recordAdmin(AuditEventTypes.TENANT_VERIFICATION_REQUESTED, currentActor(),
                AuditEventTypes.TARGET_TENANT, String.valueOf(tenant.getId()),
                AuditService.meta("slug", tenant.getSlug(),
                        "contact_email", contactEmail,
                        "invalidated_pending", invalidated,
                        "expires_at", row.getExpiresAt().toString()));
    }

    /**
     * Consume a verification token. Unauthenticated — the bearer of
     * the email-delivered token IS the proof of email control. On
     * success the tenant's {@code verified_at} is set, the token is
     * marked used, and the result carries the tenant slug so the
     * caller can render a "you've verified X" success page.
     *
     * @throws IllegalArgumentException token unknown, expired, or used
     */
    @Transactional
    public VerificationResult consumeToken(String rawToken) {
        if (rawToken == null || rawToken.isBlank()) {
            throw new IllegalArgumentException("Invalid or expired verification token");
        }
        String hash = sha256Hex(rawToken);
        TenantVerificationToken row = tokenRepository.findByTokenHash(hash)
                .orElseThrow(() -> new IllegalArgumentException("Invalid or expired verification token"));

        LocalDateTime now = LocalDateTime.now();
        if (row.getUsedAt() != null) {
            throw new IllegalArgumentException("Invalid or expired verification token");
        }
        if (row.getExpiresAt().isBefore(now)) {
            throw new IllegalArgumentException("Invalid or expired verification token");
        }

        Tenant tenant = row.getTenant();
        boolean wasVerified = tenant.getVerifiedAt() != null;
        tenant.setVerifiedAt(now);
        // No user actor on this path — the click-through is anonymous.
        // V2b will set verified_by_user_id to a "system_email_challenge"
        // sentinel; today we leave it null to make the audit trail
        // honest about who clicked.
        tenant.setVerifiedByUserId(null);
        tenantRepository.save(tenant);

        row.setUsedAt(now);
        tokenRepository.save(row);

        auditService.recordAdmin(AuditEventTypes.TENANT_VERIFIED, null,
                AuditEventTypes.TARGET_TENANT, String.valueOf(tenant.getId()),
                AuditService.meta("slug", tenant.getSlug(),
                        "channel", "email_challenge",
                        "contact_email", row.getContactEmail(),
                        "re_verification", wasVerified));

        return new VerificationResult(tenant.getSlug(),
                tenant.getDisplayName() != null ? tenant.getDisplayName() : tenant.getName());
    }

    public record VerificationResult(String slug, String displayName) {}

    // ── helpers ──────────────────────────────────────────────────────

    private static String tenantLabel(Tenant t) {
        return t.getDisplayName() != null && !t.getDisplayName().isBlank()
                ? t.getDisplayName()
                : t.getName();
    }

    private static String buildEmailBody(Tenant tenant, String verifyUrl) {
        return "A request was made to verify ownership of the WeldForge tenant '"
              + tenantLabel(tenant) + "' (slug: " + tenant.getSlug() + ").\n\n"
              + "If you initiated this, confirm by opening this link:\n"
              + verifyUrl + "\n\n"
              + "The link expires in " + EXPIRY_HOURS + " hours and can be used once.\n\n"
              + "If you did NOT initiate this verification, you can safely ignore this email — "
              + "no change is made to the tenant until the link is clicked.";
    }

    private static String generateRandomToken() {
        byte[] buf = new byte[TOKEN_BYTES];
        new SecureRandom().nextBytes(buf);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(buf);
    }

    static String sha256Hex(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(input.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    private User currentActor() {
        String tenantSlug = tech.cwvermaak.weldforge.config.tenant.TenantContext.get();
        var auth = SecurityContextHolder.getContext().getAuthentication();
        if (tenantSlug == null || auth == null || !(auth.getPrincipal() instanceof String email)) return null;
        return userRepository.findByTenant_SlugAndEmailIgnoreCase(tenantSlug, email).orElse(null);
    }

    private Long currentActorId() {
        User a = currentActor();
        return a == null ? null : a.getId();
    }
}
