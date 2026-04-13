package tech.cwvermaak.intellisso.service.mfa;

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
import tech.cwvermaak.intellisso.model.MfaFactor;
import tech.cwvermaak.intellisso.model.MfaFactorType;
import tech.cwvermaak.intellisso.model.User;
import tech.cwvermaak.intellisso.model.dto.MfaFactorDto;
import tech.cwvermaak.intellisso.model.dto.MfaVerifyRequestDto;
import tech.cwvermaak.intellisso.model.dto.TotpEnrollResponseDto;
import tech.cwvermaak.intellisso.repository.BackupCodeRepository;
import tech.cwvermaak.intellisso.repository.MfaFactorRepository;
import tech.cwvermaak.intellisso.repository.UserRepository;
import tech.cwvermaak.intellisso.service.JwtService;
import tech.cwvermaak.intellisso.service.TwilioService;
import tech.cwvermaak.intellisso.service.audit.AuditEventTypes;
import tech.cwvermaak.intellisso.service.audit.AuditService;

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
        if (!totpService.verify(factor.getTotpSecretEnc(), code)) {
            throw new BadCredentialsException("Invalid code");
        }
        factor.setVerified(true);
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

    @Transactional
    public void deleteFactor(User user, Long factorId) {
        MfaFactor factor = mfaFactorRepository.findByIdAndUserId(factorId, user.getId())
                .orElseThrow(() -> new EntityNotFoundException("Factor " + factorId + " not found"));
        mfaFactorRepository.delete(factor);
        auditService.recordUserAction(AuditEventTypes.MFA_FACTOR_REMOVE, user,
                AuditEventTypes.TARGET_MFA_FACTOR, String.valueOf(factorId),
                AuditService.meta("type", factor.getType().name(), "label", factor.getLabel()));
    }

    /**
     * Self-service MFA reset. The caller must re-verify their password —
     * this blocks session-hijack scenarios where a stolen access token
     * could otherwise strip the rightful owner's second factor. All
     * factors and unused backup codes are wiped; re-enrollment is required
     * on the next login.
     */
    @Transactional
    public int selfReset(User user, String password) {
        if (user.getPassword() == null || password == null
                || !passwordEncoder.matches(password, user.getPassword())) {
            throw new BadCredentialsException("Password re-verification failed");
        }
        int removed = wipeFactors(user);
        auditService.recordUserAction(AuditEventTypes.MFA_SELF_RESET, user,
                AuditEventTypes.TARGET_USER, String.valueOf(user.getId()),
                AuditService.meta("removed", removed));
        return removed;
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
        Long userId;
        try {
            userId = Long.valueOf(claims.getSubject());
        } catch (NumberFormatException e) {
            throw new AccessDeniedException("Malformed MFA challenge subject");
        }
        return userRepository.findById(userId)
                .orElseThrow(() -> new AccessDeniedException("User no longer exists"));
    }

    public void recordChallengeFailure(User user, MfaFactorType type) {
        auditService.log(tech.cwvermaak.intellisso.model.AuditEvent.builder()
                .eventType(AuditEventTypes.MFA_CHALLENGE_FAILED)
                .outcome(tech.cwvermaak.intellisso.model.AuditEvent.Outcome.FAILURE)
                .tenant(user != null ? user.getTenant() : null)
                .actorUser(user)
                .actorEmail(user != null ? user.getEmail() : null)
                .targetType(AuditEventTypes.TARGET_USER)
                .targetId(user != null ? String.valueOf(user.getId()) : null)
                .metadata(AuditService.meta("factor_type", type != null ? type.name() : null)));
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
            if (Boolean.TRUE.equals(f.getEnabled()) && Boolean.TRUE.equals(f.getVerified())
                    && totpService.verify(f.getTotpSecretEnc(), code)) {
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
