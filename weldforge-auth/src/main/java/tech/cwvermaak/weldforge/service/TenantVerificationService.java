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
import tech.cwvermaak.weldforge.repository.OidcClientRepository;
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
 * <p><b>V2b domain gate.</b> The challenge is auto-issued only when the
 * contact_email's domain matches one of the tenant's registered OIDC
 * {@code webOrigins}. A mismatch (a free gmail, a lookalike) is declined and
 * queued for a super-admin to vouch for via
 * {@link #approveVerificationReview(Long)} — so a malicious operator can no
 * longer self-verify by claiming an inbox unrelated to the tenant. A
 * super-admin initiating the request is the review authority and skips the
 * gate. V2a moved the trust anchor from "super-admin says so" to "someone
 * reachable at the claimed email says so"; V2b adds "and that email belongs to
 * the tenant".</p>
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
    private final OidcClientRepository oidcClientRepository;

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
    public VerificationRequestOutcome requestVerification(Long tenantId) {
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

        // V2b domain gate. The challenge only raises the trust bar if the
        // inbox it proves control of actually belongs to the tenant, so a
        // contact_email whose domain matches none of the tenant's registered
        // OIDC web origins is declined and queued for a super-admin to vouch
        // for, rather than silently verified. A super-admin initiating the
        // request is already the review authority, so they skip the gate.
        if (!tenantAccessor.isSuperAdmin()) {
            String reason = domainGateReason(tenant, contactEmail);
            if (reason != null) {
                tenant.setVerificationReviewRequired(true);
                tenant.setVerificationReviewReason(reason);
                tenantRepository.save(tenant);
                auditService.recordAdmin(AuditEventTypes.TENANT_VERIFICATION_REVIEW_REQUIRED, currentActor(),
                        AuditEventTypes.TARGET_TENANT, String.valueOf(tenant.getId()),
                        AuditService.meta("slug", tenant.getSlug(),
                                "contact_email", contactEmail,
                                "reason", reason));
                return VerificationRequestOutcome.QUEUED_FOR_REVIEW;
            }
        }

        issueChallenge(tenant, contactEmail);
        return VerificationRequestOutcome.CHALLENGE_SENT;
    }

    /**
     * Super-admin approval of a tenant the V2b gate queued for review. The
     * human vouch stands in for the domain match, so the challenge is issued
     * (which clears the review flag). SUPER_ADMIN only.
     */
    @Transactional
    public void approveVerificationReview(Long tenantId) {
        tenantAccessor.requireSuperAdmin();
        Tenant tenant = tenantRepository.findById(tenantId)
                .orElseThrow(() -> new EntityNotFoundException("Tenant " + tenantId + " not found"));
        String contactEmail = tenant.getContactEmail();
        if (contactEmail == null || contactEmail.isBlank()) {
            throw new IllegalStateException(
                "Tenant " + tenant.getSlug() + " has no contact_email to send the challenge to");
        }
        issueChallenge(tenant, contactEmail);
        auditService.recordAdmin(AuditEventTypes.TENANT_VERIFICATION_REVIEW_APPROVED, currentActor(),
                AuditEventTypes.TARGET_TENANT, String.valueOf(tenant.getId()),
                AuditService.meta("slug", tenant.getSlug(), "contact_email", contactEmail));
    }

    /**
     * Clear a tenant's review flag WITHOUT issuing a challenge. For the V2c
     * watchword case (and any review a super-admin judges benign) where the
     * answer is "looked, it's fine" rather than "send the email proof".
     * SUPER_ADMIN only.
     */
    @Transactional
    public void dismissVerificationReview(Long tenantId) {
        tenantAccessor.requireSuperAdmin();
        Tenant tenant = tenantRepository.findById(tenantId)
                .orElseThrow(() -> new EntityNotFoundException("Tenant " + tenantId + " not found"));
        String reason = tenant.getVerificationReviewReason();
        tenant.setVerificationReviewRequired(false);
        tenant.setVerificationReviewReason(null);
        tenantRepository.save(tenant);
        auditService.recordAdmin(AuditEventTypes.TENANT_VERIFICATION_REVIEW_DISMISSED, currentActor(),
                AuditEventTypes.TARGET_TENANT, String.valueOf(tenant.getId()),
                AuditService.meta("slug", tenant.getSlug(), "cleared_reason", reason));
    }

    /** The V2b review queue — tenants the domain gate declined. SUPER_ADMIN only. */
    @Transactional(readOnly = true)
    public java.util.List<ReviewQueueEntry> tenantsAwaitingReview() {
        tenantAccessor.requireSuperAdmin();
        return tenantRepository.findByVerificationReviewRequiredTrue().stream()
                .map(t -> new ReviewQueueEntry(t.getId(), t.getSlug(), tenantLabel(t),
                        t.getContactEmail(), t.getVerificationReviewReason()))
                .toList();
    }

    public enum VerificationRequestOutcome { CHALLENGE_SENT, QUEUED_FOR_REVIEW }

    public record ReviewQueueEntry(Long tenantId, String slug, String displayName,
                                   String contactEmail, String reason) {}

    /**
     * Mint, store and email a fresh challenge, clearing any pending review
     * flag. One live token per tenant: a fresh challenge cancels any
     * previously-issued but not-yet-consumed token, even if the contact_email
     * changed in between.
     */
    private void issueChallenge(Tenant tenant, String contactEmail) {
        tenant.setVerificationReviewRequired(false);
        tenant.setVerificationReviewReason(null);
        tenantRepository.save(tenant);

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
     * The V2b gate. Returns null when the contact_email domain matches one of
     * the tenant's registered OIDC web origins (auto-issue is allowed), or a
     * human-readable reason to decline otherwise. A tenant with no registered
     * web origins has nothing to match against, so it is declined too — the
     * conservative default, since that is exactly the state a bare lookalike
     * tenant is in.
     */
    private String domainGateReason(Tenant tenant, String contactEmail) {
        String emailDomain = EmailDomainPolicy.domainOf(contactEmail);
        if (emailDomain == null) {
            return "contact_email has no parseable domain";
        }
        java.util.List<String> origins = oidcClientRepository.findByTenantId(tenant.getId()).stream()
                .flatMap(c -> c.getWebOriginList().stream())
                .toList();
        if (origins.isEmpty()) {
            return "tenant has no registered OIDC web origins to match the contact_email domain against";
        }
        boolean matched = origins.stream().anyMatch(o -> originHostMatches(o, emailDomain));
        return matched ? null
                : "contact_email domain '" + emailDomain
                  + "' matches none of the tenant's registered OIDC web origins";
    }

    private static boolean originHostMatches(String webOrigin, String emailDomain) {
        String host = hostOf(webOrigin);
        if (host == null) return false;
        // Same registrable domain either way: app.acme.com ~ ops@acme.com, and
        // acme.com ~ someone@mail.acme.com.
        return host.equals(emailDomain)
                || host.endsWith("." + emailDomain)
                || emailDomain.endsWith("." + host);
    }

    private static String hostOf(String origin) {
        if (origin == null || origin.isBlank()) return null;
        try {
            String host = new java.net.URI(origin.trim()).getHost();
            return host == null ? null : host.toLowerCase(java.util.Locale.ROOT);
        } catch (java.net.URISyntaxException e) {
            return null;
        }
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
