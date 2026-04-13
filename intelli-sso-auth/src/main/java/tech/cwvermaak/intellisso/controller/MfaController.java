package tech.cwvermaak.intellisso.controller;

import com.yubico.webauthn.exception.RegistrationFailedException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;
import tech.cwvermaak.intellisso.config.tenant.TenantContext;
import tech.cwvermaak.intellisso.model.User;
import tech.cwvermaak.intellisso.model.dto.*;
import tech.cwvermaak.intellisso.repository.UserRepository;
import tech.cwvermaak.intellisso.service.AuthService;
import tech.cwvermaak.intellisso.service.mfa.BackupCodeService;
import tech.cwvermaak.intellisso.service.mfa.MfaService;
import tech.cwvermaak.intellisso.service.mfa.WebAuthnService;

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

    // ---- Challenge verification (public — the user is mid-login) ----

    @PostMapping("/verify")
    public ResponseEntity<AuthResponseDto> verify(@RequestBody MfaVerifyRequestDto req,
                                                  HttpServletRequest httpRequest,
                                                  HttpServletResponse response) {
        User user = mfaService.resolveChallenge(req.getChallengeToken());
        if (!mfaService.verifyChallenge(user, req)) {
            mfaService.recordChallengeFailure(user, req.getType());
            return ResponseEntity.status(401).build();
        }
        return ResponseEntity.ok(authService.completeMfaLogin(user, httpRequest, response));
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
        Long factorId = ((Number) body.get("factorId")).longValue();
        String code = (String) body.get("code");
        return ResponseEntity.ok(mfaService.activateTotp(user, factorId, code));
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
        String ceremonyKey = body.get("ceremonyKey");
        String publicKeyCredentialJson = body.get("publicKeyCredential");
        String label = body.getOrDefault("label", "Security key");
        var factor = webAuthnService.finishRegistration(user, ceremonyKey, publicKeyCredentialJson, label);
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

    private User requireUser(String email) {
        String tenantSlug = TenantContext.get();
        return userRepository.findByTenant_SlugAndEmailIgnoreCase(tenantSlug, email)
                .orElseThrow(() -> new IllegalStateException("User not found in current tenant"));
    }
}
