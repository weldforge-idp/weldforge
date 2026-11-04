package tech.cwvermaak.weldforge.service.mfa;

import com.yubico.webauthn.exception.AssertionFailedException;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import jakarta.persistence.EntityNotFoundException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import tech.cwvermaak.weldforge.model.MfaFactor;
import tech.cwvermaak.weldforge.model.MfaFactorType;
import tech.cwvermaak.weldforge.model.User;
import tech.cwvermaak.weldforge.model.dto.MfaFactorDto;
import tech.cwvermaak.weldforge.model.dto.MfaVerifyRequestDto;
import tech.cwvermaak.weldforge.model.dto.TotpEnrollResponseDto;
import tech.cwvermaak.weldforge.repository.BackupCodeRepository;
import tech.cwvermaak.weldforge.repository.MfaFactorRepository;
import tech.cwvermaak.weldforge.repository.UserRepository;
import tech.cwvermaak.weldforge.service.JwtService;
import tech.cwvermaak.weldforge.service.TwilioService;
import tech.cwvermaak.weldforge.service.audit.AuditEventTypes;
import tech.cwvermaak.weldforge.service.audit.AuditService;

import java.security.SecureRandom;

import java.util.Map;

import java.time.LocalDateTime;
import java.util.List;

/**
 * High-level MFA orchestration. Controllers talk to this; it coordinates
 * the factor-specific services and the challenge JWT.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class MfaService {

    private final MfaFactorRepository mfaFactorRepository;
    private final BackupCodeRepository backupCodeRepository;
    private final UserRepository userRepository;
    private final JwtService jwtService;
    private final TotpService totpService;
    private final BackupCodeService backupCodeService;
    private final WebAuthnService webAuthnService;
    private final PasswordEncoder passwordEncoder;
    private final AuditService auditService;
    private final TwilioService twilioService;
    private final tech.cwvermaak.weldforge.repository.ConsumedMfaChallengeRepository consumedMfaChallengeRepository;
    // B-AUTH-5 (F60): a failed password re-verification on the reset path is a
    // password guess, so it feeds the same per-user lockout as a failed login.
    private final tech.cwvermaak.weldforge.service.security.AccountLockoutService lockoutService;
    private final tech.cwvermaak.weldforge.service.security.FailedLoginRecorder failedLoginRecorder;

    private static final SecureRandom SMS_CODE_RNG = new SecureRandom();
    private static final long SMS_CODE_TTL_SECONDS = 300;

    // -- Enrollment / management ---------------------------------------

    public List<MfaFactorDto> listFactors(User user) {
        return mfaFactorRepository.findByUserId(user.getId()).stream()
                .map(MfaService::toDto)
                .toList();
    }

    public boolean hasVerifiedFactor(User user) {
        return !mfaFactorRepository.findByUserIdAndEnabledTrueAndVerifiedTrue(user.getId()).isEmpty();
    }

    public List<MfaFactorType> availableFactors(User user) {
        return mfaFactorRepository.findByUserIdAndEnabledTrueAndVerifiedTrue(user.getId()).stream()
                .map(MfaFactor::getType)
                .distinct()
                .toList();
    }

    @Transactional
    public TotpEnrollResponseDto enrollTotp(User user, String label) {
        try {
            String secret = totpService.generateSecret();
            String qr = totpService.generateQrDataUri(secret, user.getEmail());
            MfaFactor factor = MfaFactor.builder()
                    .user(user)
                    .type(MfaFactorType.TOTP)
                    .label(label != null && !label.isBlank() ? label : "Authenticator app")
                    .totpSecretEnc(secret)
                    .enabled(true)
                    .verified(false)
                    .build();
            factor = mfaFactorRepository.save(factor);
            auditService.recordUserAction(AuditEventTypes.MFA_FACTOR_ENROLL, user,
                    AuditEventTypes.TARGET_MFA_FACTOR, String.valueOf(factor.getId()),
                    AuditService.meta("type", "TOTP"));
            return TotpEnrollResponseDto.builder()
                    .factorId(factor.getId())
                    .secret(secret)
                    .qrDataUri(qr)
                    .build();
        } catch (Exception e) {
            throw new IllegalStateException("Failed to enroll TOTP factor", e);
        }
    }

    /** Flip a freshly-enrolled TOTP factor to verified after the user types the first OTP. */
    @Transactional
    public MfaFactorDto activateTotp(User user, Long factorId, String code) {
        MfaFactor factor = mfaFactorRepository.findByIdAndUserId(factorId, user.getId())
                .orElseThrow(() -> new EntityNotFoundException("Factor " + factorId + " not found"));
        if (factor.getType() != MfaFactorType.TOTP) {
            throw new IllegalArgumentException("Factor is not a TOTP factor");
        }
        java.util.OptionalLong step = totpService.matchingStep(factor.getTotpSecretEnc(), code);
        if (step.isEmpty()) {
            throw new BadCredentialsException("Invalid code");
        }
        factor.setVerified(true);
        // Record the activation step so the same code can't be replayed for the
        // first login (RFC 6238 anti-replay).
        factor.setLastTotpStep(step.getAsLong());
        factor.setLastUsedAt(LocalDateTime.now());
        auditService.recordUserAction(AuditEventTypes.MFA_FACTOR_ACTIVATE, user,
                AuditEventTypes.TARGET_MFA_FACTOR, String.valueOf(factor.getId()),
                AuditService.meta("type", factor.getType().name()));
        return toDto(factor);
    }

    // -- SMS OTP --------------------------------------------------------

    /**
     * Enroll a new SMS factor. Creates the factor in unverified state with a
     * pending OTP code, sends the code via the tenant's Twilio config. The
     * user activates the factor by calling {@link #activateSms} with the code.
     */
    @Transactional
    public MfaFactorDto enrollSms(User user, String phoneNumber, String label) {
        if (phoneNumber == null || phoneNumber.isBlank()) {
            throw new IllegalArgumentException("phoneNumber is required");
        }
        if (!phoneNumber.startsWith("+")) {
            throw new IllegalArgumentException("phoneNumber must be in E.164 format (e.g. +27821234567)");
        }
        String normalised = phoneNumber.trim();

        String code = generateSmsCode();
        String codeHash = passwordEncoder.encode(code);
        LocalDateTime expires = LocalDateTime.now().plusSeconds(SMS_CODE_TTL_SECONDS);

        MfaFactor factor = MfaFactor.builder()
                .user(user)
                .type(MfaFactorType.SMS)
                .label(label != null && !label.isBlank() ? label : "Phone " + maskPhone(normalised))
                .phoneNumber(normalised)
                .smsCodeHash(codeHash)
                .smsCodeExpiresAt(expires)
                .enabled(true)
                .verified(false)
                .build();
        factor = mfaFactorRepository.save(factor);

        twilioService.sendSms(user.getTenant(), normalised,
                "Your WeldForge verification code is " + code
                        + ". It expires in " + (SMS_CODE_TTL_SECONDS / 60) + " minutes.");

        auditService.recordUserAction(AuditEventTypes.MFA_FACTOR_ENROLL, user,
                AuditEventTypes.TARGET_MFA_FACTOR, String.valueOf(factor.getId()),
                AuditService.meta("type", "SMS", "phone", maskPhone(normalised)));
        auditService.recordUserAction(AuditEventTypes.MFA_SMS_CODE_SENT, user,
                AuditEventTypes.TARGET_MFA_FACTOR, String.valueOf(factor.getId()),
                AuditService.meta("phone", maskPhone(normalised)));

        return toDto(factor);
    }

    /** Activate a freshly-enrolled SMS factor after the user types the first OTP. */
    @Transactional
    public MfaFactorDto activateSms(User user, Long factorId, String code) {
        MfaFactor factor = mfaFactorRepository.findByIdAndUserId(factorId, user.getId())
                .orElseThrow(() -> new EntityNotFoundException("Factor " + factorId + " not found"));
        if (factor.getType() != MfaFactorType.SMS) {
            throw new IllegalArgumentException("Factor is not an SMS factor");
        }
        if (factor.getSmsCodeHash() == null || factor.getSmsCodeExpiresAt() == null
                || factor.getSmsCodeExpiresAt().isBefore(LocalDateTime.now())) {
            throw new BadCredentialsException("SMS code expired — resend and try again");
        }
        if (code == null || !passwordEncoder.matches(code, factor.getSmsCodeHash())) {
            throw new BadCredentialsException("Invalid code");
        }

        factor.setVerified(true);
        factor.setSmsCodeHash(null);
        factor.setSmsCodeExpiresAt(null);
        factor.setLastUsedAt(LocalDateTime.now());

        auditService.recordUserAction(AuditEventTypes.MFA_FACTOR_ACTIVATE, user,
                AuditEventTypes.TARGET_MFA_FACTOR, String.valueOf(factor.getId()),
                AuditService.meta("type", "SMS"));
        return toDto(factor);
    }

    /**
     * Send a fresh OTP code to an existing verified SMS factor. Used both
     * during step-up auth and to recover from an expired enrollment code.
     */
    @Transactional
    public void sendSmsChallenge(User user, Long factorId) {
        MfaFactor factor = mfaFactorRepository.findByIdAndUserId(factorId, user.getId())
                .orElseThrow(() -> new EntityNotFoundException("Factor " + factorId + " not found"));
        if (factor.getType() != MfaFactorType.SMS) {
            throw new IllegalArgumentException("Factor is not an SMS factor");
        }

        String code = generateSmsCode();
        factor.setSmsCodeHash(passwordEncoder.encode(code));
        factor.setSmsCodeExpiresAt(LocalDateTime.now().plusSeconds(SMS_CODE_TTL_SECONDS));

        twilioService.sendSms(user.getTenant(), factor.getPhoneNumber(),
                "Your WeldForge verification code is " + code + ".");

        auditService.recordUserAction(AuditEventTypes.MFA_SMS_CODE_SENT, user,
                AuditEventTypes.TARGET_MFA_FACTOR, String.valueOf(factor.getId()),
                AuditService.meta("phone", maskPhone(factor.getPhoneNumber())));
    }

    /**
     * Remove one factor.
     *
     * <p>Refuses when the target is the caller's last verified, enabled factor
     * (B-AUTH-5, F60). This route takes a path variable and an access token and
     * asks for nothing else, so without the guard it is a cheaper way to strip
     * MFA than {@link #selfReset} — which is the endpoint built to demand
     * proof. Turning MFA off is allowed; doing it without proving you still
     * hold a factor is not, so the caller is sent to the reset instead.
     *
     * <p>The guard keys on verified <em>and</em> enabled factors, which is what
     * keeps the enrollment-cancel path working: a half-finished TOTP enrollment
     * is unverified, so abandoning it is unaffected. Keying on "the last row"
     * would have left a user unable to back out of a setup they mistyped.
     *
     * <p>Removing a non-last factor still needs only the token. That cannot
     * take the account to zero factors, every removal is audited, and the
     * alternative is a DELETE with a request body. Accepted residual, recorded
     * in the backlog.
     */
    @Transactional
    public void deleteFactor(User user, Long factorId) {
        MfaFactor factor = mfaFactorRepository.findByIdAndUserId(factorId, user.getId())
                .orElseThrow(() -> new EntityNotFoundException("Factor " + factorId + " not found"));
        if (isLastVerifiedFactor(user, factor)) {
            auditService.recordUserAction(AuditEventTypes.MFA_SELF_RESET_DENIED, user,
                    AuditEventTypes.TARGET_MFA_FACTOR, String.valueOf(factorId),
                    AuditService.meta("reason", "last_verified_factor", "route", "delete_factor"));
            throw new LastFactorProtectedException();
        }
        mfaFactorRepository.delete(factor);
        auditService.recordUserAction(AuditEventTypes.MFA_FACTOR_REMOVE, user,
                AuditEventTypes.TARGET_MFA_FACTOR, String.valueOf(factorId),
                AuditService.meta("type", factor.getType().name(), "label", factor.getLabel()));
    }

    /** Response to any refused reset. Deliberately says which of the two it was not. */
    private static final String RESET_REFUSED = "Password or verification code incorrect";

    /**
     * Self-service MFA reset. Wipes every factor and unused backup code;
     * re-enrollment is required on the next login.
     *
     * <p><strong>Requires the password and a current factor proof together</strong>
     * (B-AUTH-5, F60). The password alone used to be enough, which made this a
     * downgrade to no-MFA available to anyone holding a stolen access token and
     * the password — and the password is exactly what MFA exists to survive.
     *
     * <p>The proof goes through {@link #verifyChallenge}, so a TOTP code, an SMS
     * code, a WebAuthn assertion or a <em>backup code</em> all satisfy it.
     * Backup codes counting is the point rather than a concession: this endpoint
     * exists for the lost-authenticator case, and demanding an authenticator
     * proof would mean demanding the thing the user has just lost. Lost
     * everything is {@link #adminReset}, out of band, by a human.
     *
     * <p>An account with <em>no</em> verified factor resets on the password
     * alone. There is nothing to protect and no proof it could supply, and
     * requiring one would strand precisely the accounts that are not at risk.
     * The invariant still holds: such an account is already unprotected, so the
     * transition this guard forbids cannot happen.
     *
     * <p>Both refusals return one indistinguishable 401, so the endpoint cannot
     * confirm a password independently of a factor. They are separate events in
     * the audit log, and they feed different counters on purpose: a wrong
     * password is the same event as a wrong password at {@code /api/auth/login}
     * and feeds the account lockout; a wrong code is the same event as a wrong
     * code at {@code /api/auth/mfa/verify}.
     */
    @Transactional
    public int selfReset(User user, String password, MfaVerifyRequestDto proof) {
        // Before the password is read, as at login: otherwise lockout stops
        // guessing at the front door while this endpoint keeps answering.
        lockoutService.ensureNotLocked(user);

        if (user.getPassword() == null || password == null
                || !passwordEncoder.matches(password, user.getPassword())) {
            failedLoginRecorder.badResetPassword(user);
            throw new BadCredentialsException(RESET_REFUSED);
        }

        List<MfaFactor> protectedBy =
                mfaFactorRepository.findByUserIdAndEnabledTrueAndVerifiedTrue(user.getId());
        if (!protectedBy.isEmpty()) {
            if (proof == null || !verifyChallenge(user, proof)) {
                MfaFactorType attempted = proof != null ? proof.getType() : null;
                recordChallengeFailure(user, attempted);
                auditService.recordUserAction(AuditEventTypes.MFA_SELF_RESET_DENIED, user,
                        AuditEventTypes.TARGET_USER, String.valueOf(user.getId()),
                        AuditService.meta("reason", "factor_proof_failed",
                                "factors_held", protectedBy.size()));
                throw new BadCredentialsException(RESET_REFUSED);
            }
        }

        int removed = wipeFactors(user);
        auditService.recordUserAction(AuditEventTypes.MFA_SELF_RESET, user,
                AuditEventTypes.TARGET_USER, String.valueOf(user.getId()),
                AuditService.meta("removed", removed,
                        "proof", protectedBy.isEmpty() ? "none_held" : "verified"));
        return removed;
    }

    /**
     * True when this factor is the only thing standing between the account and
     * no MFA at all. Uses the same predicate as {@link #hasVerifiedFactor}, so
     * the two cannot drift apart.
     */
    private boolean isLastVerifiedFactor(User user, MfaFactor factor) {
        if (!Boolean.TRUE.equals(factor.getEnabled()) || !Boolean.TRUE.equals(factor.getVerified())) {
            return false;
        }
        List<MfaFactor> verified =
                mfaFactorRepository.findByUserIdAndEnabledTrueAndVerifiedTrue(user.getId());
        return verified.size() <= 1;
    }

    /**
     * Administrative reset. Called from AdminService after the same-tenant
     * check has already been enforced. Returns the count of factors removed
     * for the caller to echo back to the UI.
     */
    @Transactional
    public int adminReset(User actor, User target) {
        int removed = wipeFactors(target);
        Map<String, Object> metadata = AuditService.meta(
                "removed", removed,
                "target_email", target.getEmail(),
                "target_user_id", target.getId(),
                "target_tenant", target.getTenant() != null ? target.getTenant().getSlug() : null
        );
        auditService.recordAdmin(AuditEventTypes.MFA_ADMIN_RESET, actor,
                AuditEventTypes.TARGET_USER, String.valueOf(target.getId()), metadata);
        return removed;
    }

    private int wipeFactors(User user) {
        int count = mfaFactorRepository.findByUserId(user.getId()).size();
        mfaFactorRepository.deleteAll(mfaFactorRepository.findByUserId(user.getId()));
        backupCodeRepository.deleteAllByUserId(user.getId());
        return count;
    }

    // -- Challenge flow ------------------------------------------------

    /**
     * Parse and validate a challenge token, returning the user it's bound
     * to. Throws if the token is expired, not an mfa_challenge, or the user
     * no longer exists.
     */
    public User resolveChallenge(String challengeToken) {
        if (challengeToken == null || challengeToken.isBlank()) {
            throw new AccessDeniedException("Missing MFA challenge token");
        }
        Claims claims;
        try {
            claims = jwtService.parse(challengeToken);
        } catch (JwtException | IllegalArgumentException e) {
            throw new AccessDeniedException("Invalid MFA challenge token");
        }
        if (!jwtService.isMfaChallenge(claims)) {
            throw new AccessDeniedException("Not an MFA challenge token");
        }
        // Single-use guard (B-MFA-2): a challenge token already spent on a
        // successful login cannot be replayed. Legacy tokens minted before the
        // jti was added (during a deploy rollover) have no id — skip the check.
        String jti = claims.getId();
        if (jti != null && !jti.isBlank() && consumedMfaChallengeRepository.existsById(jti)) {
            throw new AccessDeniedException("MFA challenge already used");
        }
        Long userId;
        try {
            userId = Long.valueOf(claims.getSubject());
        } catch (NumberFormatException e) {
            throw new AccessDeniedException("Malformed MFA challenge subject");
        }
        return userRepository.findById(userId)
                .orElseThrow(() -> new AccessDeniedException("User no longer exists"));
    }

    /**
     * Mark a challenge token as spent (B-MFA-2). Call this exactly once, after
     * the second factor has been verified, so the same token cannot complete
     * login again. No-op for tokens without a jti (legacy) or already recorded.
     */
    @Transactional
    public void consumeChallenge(String challengeToken) {
        if (challengeToken == null || challengeToken.isBlank()) return;
        Claims claims;
        try {
            claims = jwtService.parse(challengeToken);
        } catch (JwtException | IllegalArgumentException e) {
            return;
        }
        String jti = claims.getId();
        if (jti == null || jti.isBlank()) return;
        if (consumedMfaChallengeRepository.existsById(jti)) return;
        LocalDateTime expiresAt = claims.getExpiration() == null
                ? LocalDateTime.now().plusMinutes(10)
                : LocalDateTime.ofInstant(claims.getExpiration().toInstant(),
                        java.time.ZoneId.systemDefault());
        consumedMfaChallengeRepository.save(
                tech.cwvermaak.weldforge.model.ConsumedMfaChallenge.builder()
                        .jti(jti)
                        .expiresAt(expiresAt)
                        .consumedAt(LocalDateTime.now())
                        .build());
    }

    public void recordChallengeFailure(User user, MfaFactorType type) {
        auditService.log(tech.cwvermaak.weldforge.model.AuditEvent.builder()
                .eventType(AuditEventTypes.MFA_CHALLENGE_FAILED)
                .outcome(tech.cwvermaak.weldforge.model.AuditEvent.Outcome.FAILURE)
                .tenant(user != null ? user.getTenant() : null)
                .actorUser(user)
                .actorEmail(user != null ? user.getEmail() : null)
                .targetType(AuditEventTypes.TARGET_USER)
                .targetId(user != null ? String.valueOf(user.getId()) : null)
                .metadata(AuditService.meta("factor_type", type != null ? type.name() : null)));
    }

    /**
     * Record an MFA verification attempt that was refused before any code
     * was checked because the account is inside a lockout window — the
     * brute-force guard tripping. Distinct from {@link #recordChallengeFailure}
     * (a wrong code) so the two are separable in the audit trail.
     */
    public void recordChallengeBlocked(User user) {
        auditService.log(tech.cwvermaak.weldforge.model.AuditEvent.builder()
                .eventType(AuditEventTypes.MFA_CHALLENGE_BLOCKED)
                .outcome(tech.cwvermaak.weldforge.model.AuditEvent.Outcome.DENIED)
                .tenant(user != null ? user.getTenant() : null)
                .actorUser(user)
                .actorEmail(user != null ? user.getEmail() : null)
                .targetType(AuditEventTypes.TARGET_USER)
                .targetId(user != null ? String.valueOf(user.getId()) : null)
                .metadata(AuditService.meta("reason", "account_locked")));
    }

    /**
     * Verify the presented second factor. Returns true on success; the
     * caller should then issue an access token.
     */
    @Transactional
    public boolean verifyChallenge(User user, MfaVerifyRequestDto req) {
        // Backup code path — independent of the requested type.
        if (req.getBackupCode() != null && !req.getBackupCode().isBlank()) {
            return backupCodeService.consume(user, req.getBackupCode());
        }

        MfaFactorType type = req.getType();
        if (type == null) return false;

        return switch (type) {
            case TOTP -> verifyTotp(user, req.getCode());
            case WEBAUTHN -> verifyWebAuthn(user, req.getChallengeToken(), req.getWebauthnResponse());
            case SMS -> verifySms(user, req.getCode());
        };
    }

    private boolean verifySms(User user, String code) {
        if (code == null || code.isBlank()) return false;
        for (MfaFactor f : mfaFactorRepository.findByUserIdAndType(user.getId(), MfaFactorType.SMS)) {
            if (!Boolean.TRUE.equals(f.getEnabled()) || !Boolean.TRUE.equals(f.getVerified())) continue;
            if (f.getSmsCodeHash() == null || f.getSmsCodeExpiresAt() == null) continue;
            if (f.getSmsCodeExpiresAt().isBefore(LocalDateTime.now())) continue;
            if (passwordEncoder.matches(code, f.getSmsCodeHash())) {
                // Single-use — clear the code on success.
                f.setSmsCodeHash(null);
                f.setSmsCodeExpiresAt(null);
                f.setLastUsedAt(LocalDateTime.now());
                return true;
            }
        }
        return false;
    }

    private boolean verifyTotp(User user, String code) {
        if (code == null || code.isBlank()) return false;
        for (MfaFactor f : mfaFactorRepository.findByUserIdAndType(user.getId(), MfaFactorType.TOTP)) {
            if (Boolean.TRUE.equals(f.getEnabled()) && Boolean.TRUE.equals(f.getVerified())) {
                java.util.OptionalLong step = totpService.matchingStep(f.getTotpSecretEnc(), code);
                if (step.isEmpty()) continue;
                long s = step.getAsLong();
                // RFC 6238 anti-replay: reject a code whose time-step was already
                // accepted (covers replay of the same code within its ±1 window).
                if (f.getLastTotpStep() != null && s <= f.getLastTotpStep()) {
                    log.warn("Rejected replayed TOTP code for factor {} (step {} <= last accepted {})",
                            f.getId(), s, f.getLastTotpStep());
                    continue;
                }
                f.setLastTotpStep(s);
                f.setLastUsedAt(LocalDateTime.now());
                return true;
            }
        }
        return false;
    }

    private boolean verifyWebAuthn(User user, String challengeToken, String responseJson) {
        if (responseJson == null || responseJson.isBlank()) return false;
        try {
            return webAuthnService.finishAssertion(user, challengeToken, responseJson);
        } catch (AssertionFailedException e) {
            log.warn("WebAuthn assertion failed for user {}: {}", user.getEmail(), e.getMessage());
            return false;
        } catch (Exception e) {
            log.error("WebAuthn verification error for user {}", user.getEmail(), e);
            return false;
        }
    }

    // -- SMS helpers ---------------------------------------------------

    private static String generateSmsCode() {
        int n = SMS_CODE_RNG.nextInt(1_000_000);
        return String.format("%06d", n);
    }

    private static String maskPhone(String phone) {
        if (phone == null || phone.length() < 4) return "***";
        return "*".repeat(Math.max(0, phone.length() - 4)) + phone.substring(phone.length() - 4);
    }

    // -- Mapping -------------------------------------------------------

    private static MfaFactorDto toDto(MfaFactor f) {
        return MfaFactorDto.builder()
                .id(f.getId())
                .type(f.getType())
                .label(f.getLabel())
                .enabled(f.getEnabled())
                .verified(f.getVerified())
                .createdAt(f.getCreatedAt())
                .lastUsedAt(f.getLastUsedAt())
                .phoneMasked(f.getType() == MfaFactorType.SMS ? maskPhone(f.getPhoneNumber()) : null)
                .build();
    }
}
