package tech.cwvermaak.weldforge.controller;

import com.yubico.webauthn.exception.RegistrationFailedException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;
import tech.cwvermaak.weldforge.config.tenant.TenantContext;
import tech.cwvermaak.weldforge.model.MfaFactor;
import tech.cwvermaak.weldforge.model.User;
import tech.cwvermaak.weldforge.model.dto.*;
import tech.cwvermaak.weldforge.repository.UserRepository;
import tech.cwvermaak.weldforge.service.AuthService;
import tech.cwvermaak.weldforge.service.mfa.BackupCodeService;
import tech.cwvermaak.weldforge.service.mfa.MfaService;
import tech.cwvermaak.weldforge.service.mfa.WebAuthnService;
import tech.cwvermaak.weldforge.service.security.AccountLockoutService;

import java.io.IOException;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/auth/mfa")
@RequiredArgsConstructor
public class MfaController {

    private final MfaService mfaService;
    private final BackupCodeService backupCodeService;
    private final WebAuthnService webAuthnService;
    private final UserRepository userRepository;
    private final AuthService authService;
    private final AccountLockoutService lockoutService;

    // ---- Challenge verification (public — the user is mid-login) ----

    @PostMapping("/verify")
    public ResponseEntity<AuthResponseDto> verify(@RequestBody MfaVerifyRequestDto req,
                                                  HttpServletRequest httpRequest,
                                                  HttpServletResponse response) {
        User user = mfaService.resolveChallenge(req.getChallengeToken());

        // Brute-force guard. A 6-digit TOTP/SMS code is guessable inside the
        // 5-minute challenge window if attempts are uncapped. Failed factor
        // attempts feed the same per-user lockout counter as failed
        // passwords, so an account under attack locks after the configured
        // threshold no matter which step the attacker is probing — and a
        // locked account is refused here before any code is checked.
        if (lockoutService.isLocked(user)) {
            mfaService.recordChallengeBlocked(user);
            return ResponseEntity.status(429).build();
        }
        if (!mfaService.verifyChallenge(user, req)) {
            mfaService.recordChallengeFailure(user, req.getType());
            lockoutService.recordFailure(user);
            return ResponseEntity.status(401).build();
        }
        // Second factor satisfied — clear the failed-attempt counter so the
        // password leg's earlier reset is not undone by interim MFA misses.
        lockoutService.recordSuccess(user);
        // Spend the challenge token so it can't be replayed (B-MFA-2).
        mfaService.consumeChallenge(req.getChallengeToken());
        // Report the factor that was actually satisfied. verifyChallenge takes
        // the backup-code path independently of the requested type, so the
        // amr must be derived the same way rather than from req.getType().
        boolean backupCode = req.getBackupCode() != null && !req.getBackupCode().isBlank();
        return ResponseEntity.ok(authService.completeMfaLogin(
                user, req.getType(), backupCode, httpRequest, response));
    }

    /** Start a WebAuthn assertion ceremony while mid-login. */
    @PostMapping("/webauthn/assertion/start")
    public ResponseEntity<Map<String, String>> startAssertion(@RequestBody Map<String, String> body) {
        String challengeToken = body.get("challengeToken");
        User user = mfaService.resolveChallenge(challengeToken);
        String optionsJson = webAuthnService.startAssertion(user, challengeToken);
        return ResponseEntity.ok(Map.of("publicKey", optionsJson));
    }

    // ---- Enrollment + management (requires a full access token) ----

    @GetMapping("/factors")
    public ResponseEntity<List<MfaFactorDto>> listFactors(@AuthenticationPrincipal String email) {
        User user = requireUser(email);
        return ResponseEntity.ok(mfaService.listFactors(user));
    }

    @DeleteMapping("/factors/{id}")
    public ResponseEntity<Void> deleteFactor(@AuthenticationPrincipal String email, @PathVariable Long id) {
        User user = requireUser(email);
        mfaService.deleteFactor(user, id);
        return ResponseEntity.noContent().build();
    }

    // TOTP -------------------------------------------------------------

    @PostMapping("/totp/enroll")
    public ResponseEntity<TotpEnrollResponseDto> enrollTotp(@AuthenticationPrincipal String email,
                                                            @RequestBody(required = false) Map<String, String> body) {
        User user = requireUser(email);
        String label = body != null ? body.get("label") : null;
        return ResponseEntity.ok(mfaService.enrollTotp(user, label));
    }

    @PostMapping("/totp/activate")
    public ResponseEntity<MfaFactorDto> activateTotp(@AuthenticationPrincipal String email,
                                                     @RequestBody Map<String, Object> body) {
        User user = requireUser(email);
        return ResponseEntity.ok(mfaService.activateTotp(user, factorId(body), string(body, "code")));
    }

    // SMS --------------------------------------------------------------

    @PostMapping("/sms/enroll")
    public ResponseEntity<MfaFactorDto> enrollSms(@AuthenticationPrincipal String email,
                                                   @RequestBody Map<String, String> body) {
        User user = requireUser(email);
        String phone = body != null ? body.get("phoneNumber") : null;
        String label = body != null ? body.get("label") : null;
        return ResponseEntity.ok(mfaService.enrollSms(user, phone, label));
    }

    @PostMapping("/sms/activate")
    public ResponseEntity<MfaFactorDto> activateSms(@AuthenticationPrincipal String email,
                                                     @RequestBody Map<String, Object> body) {
        User user = requireUser(email);
        return ResponseEntity.ok(mfaService.activateSms(user, factorId(body), string(body, "code")));
    }

    @PostMapping("/sms/send")
    public ResponseEntity<Void> sendSmsChallenge(@AuthenticationPrincipal String email,
                                                  @RequestBody Map<String, Object> body) {
        User user = requireUser(email);
        mfaService.sendSmsChallenge(user, factorId(body));
        return ResponseEntity.noContent().build();
    }

    // Self-service reset -----------------------------------------------

    @PostMapping("/reset")
    public ResponseEntity<Map<String, Object>> selfReset(
            @AuthenticationPrincipal String email,
            @RequestBody Map<String, String> body) {
        User user = requireUser(email);
        String password = body != null ? body.get("password") : null;
        int removed = mfaService.selfReset(user, password);
        return ResponseEntity.ok(Map.of("removed", removed));
    }

    // Backup codes -----------------------------------------------------

    @PostMapping("/backup-codes/regenerate")
    public ResponseEntity<Map<String, Object>> regenerateBackupCodes(@AuthenticationPrincipal String email) {
        User user = requireUser(email);
        List<String> codes = backupCodeService.regenerate(user);
        return ResponseEntity.ok(Map.of(
                "codes", codes,
                "remaining", codes.size()
        ));
    }

    @GetMapping("/backup-codes")
    public ResponseEntity<Map<String, Long>> backupCodeStatus(@AuthenticationPrincipal String email) {
        User user = requireUser(email);
        return ResponseEntity.ok(Map.of("remaining", backupCodeService.remaining(user.getId())));
    }

    // WebAuthn enrollment ---------------------------------------------

    @PostMapping("/webauthn/registration/start")
    public ResponseEntity<Map<String, String>> startWebauthnRegistration(
            @AuthenticationPrincipal String email,
            @RequestBody(required = false) Map<String, String> body) {
        User user = requireUser(email);
        // The enrollment ceremony uses the access-token-derived user directly,
        // so we mint a fresh short-lived token purely as a cache key.
        String cacheKey = authService.issueEnrollmentCeremonyKey(user);
        String optionsJson = webAuthnService.startRegistration(user, cacheKey);
        return ResponseEntity.ok(Map.of(
                "ceremonyKey", cacheKey,
                "publicKey", optionsJson
        ));
    }

    @PostMapping("/webauthn/registration/finish")
    public ResponseEntity<MfaFactorDto> finishWebauthnRegistration(
            @AuthenticationPrincipal String email,
            @RequestBody Map<String, String> body) throws RegistrationFailedException, IOException {
        User user = requireUser(email);
        String ceremonyKey = AuthController.required(body, "ceremonyKey");
        String publicKeyCredentialJson = AuthController.required(body, "publicKeyCredential");
        String label = body.getOrDefault("label", "Security key");
        MfaFactor factor;
        try {
            factor = webAuthnService.finishRegistration(user, ceremonyKey, publicKeyCredentialJson, label);
        } catch (IOException e) {
            // Unparseable credential JSON from the browser: the client's fault.
            throw new IllegalArgumentException("publicKeyCredential is not a valid WebAuthn response");
        }
        return ResponseEntity.ok(MfaFactorDto.builder()
                .id(factor.getId())
                .type(factor.getType())
                .label(factor.getLabel())
                .enabled(factor.getEnabled())
                .verified(factor.getVerified())
                .createdAt(factor.getCreatedAt())
                .build());
    }

    // -- helpers -------------------------------------------------------

    /**
     * The required numeric {@code factorId}. These handlers used to cast
     * {@code body.get("factorId")} straight to {@code Number}, so a missing or
     * mistyped id was a NullPointer / ClassCast 500 (B-API-2).
     */
    static long factorId(Map<String, Object> body) {
        Object v = body == null ? null : body.get("factorId");
        if (v instanceof Number n) return n.longValue();
        if (v instanceof String s && s.matches("\\d{1,18}")) return Long.parseLong(s);
        throw new IllegalArgumentException("factorId is required and must be a number");
    }

    /** An optional string member; present but not a string is a 400. */
    static String string(Map<String, Object> body, String field) {
        Object v = body == null ? null : body.get(field);
        if (v == null || v instanceof String) return (String) v;
        throw new IllegalArgumentException(field + " must be a string");
    }

    private User requireUser(String email) {
        String tenantSlug = TenantContext.get();
        return userRepository.findByTenant_SlugAndEmailIgnoreCase(tenantSlug, email)
                .orElseThrow(() -> new IllegalStateException("User not found in current tenant"));
    }
}
