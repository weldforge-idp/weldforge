package tech.cwvermaak.intellisso.service.mfa;

import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import tech.cwvermaak.intellisso.model.BackupCode;
import tech.cwvermaak.intellisso.model.User;
import tech.cwvermaak.intellisso.repository.BackupCodeRepository;
import tech.cwvermaak.intellisso.service.audit.AuditEventTypes;
import tech.cwvermaak.intellisso.service.audit.AuditService;

import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

/**
 * Backup-code factor — a set of single-use recovery codes that bypass TOTP /
 * WebAuthn when the user's primary factor is unavailable. Codes are only
 * shown to the user once at generation time; only BCrypt hashes are persisted.
 */
@Service
@RequiredArgsConstructor
public class BackupCodeService {

    private static final int CODES_PER_SET = 10;
    private static final SecureRandom RNG = new SecureRandom();
    // Unambiguous alphabet: no I/O/0/1/l.
    private static final char[] ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789".toCharArray();

    private final BackupCodeRepository backupCodeRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuditService auditService;

    /**
     * Rotate the user's backup codes: delete any existing set and generate
     * a fresh set. The returned plaintext codes must be shown to the user
     * exactly once and never persisted.
     */
    @Transactional
    public List<String> regenerate(User user) {
        backupCodeRepository.deleteAllByUserId(user.getId());

        List<String> plaintextCodes = new ArrayList<>(CODES_PER_SET);
        List<BackupCode> rows = new ArrayList<>(CODES_PER_SET);
        for (int i = 0; i < CODES_PER_SET; i++) {
            String display = generateCode();                  // shown to user: XXXXX-XXXXX
            String canonical = normalise(display);            // hashed: XXXXXXXXXX
            plaintextCodes.add(display);
            rows.add(BackupCode.builder()
                    .user(user)
                    .codeHash(passwordEncoder.encode(canonical))
                    .build());
        }
        backupCodeRepository.saveAll(rows);
        auditService.recordUserAction(AuditEventTypes.MFA_BACKUP_CODES_REGENERATED, user,
                AuditEventTypes.TARGET_USER, String.valueOf(user.getId()),
                AuditService.meta("count", CODES_PER_SET));
        return plaintextCodes;
    }

    /**
     * Try to redeem a plaintext backup code. Returns true on success; the
     * matched row is atomically marked used so it cannot be replayed.
     */
    @Transactional
    public boolean consume(User user, String submitted) {
        if (submitted == null || submitted.isBlank()) return false;
        String normalised = normalise(submitted);

        for (BackupCode code : backupCodeRepository.findByUserIdAndUsedAtIsNull(user.getId())) {
            if (passwordEncoder.matches(normalised, code.getCodeHash())) {
                code.setUsedAt(LocalDateTime.now());
                backupCodeRepository.save(code);
                return true;
            }
        }
        return false;
    }

    public long remaining(Long userId) {
        return backupCodeRepository.countByUserIdAndUsedAtIsNull(userId);
    }

    private static String generateCode() {
        // 10 chars, grouped 5-5 for readability: XXXXX-XXXXX
        char[] buf = new char[10];
        for (int i = 0; i < buf.length; i++) {
            buf[i] = ALPHABET[RNG.nextInt(ALPHABET.length)];
        }
        return new String(buf, 0, 5) + "-" + new String(buf, 5, 5);
    }

    /** Canonical form used for hashing + comparison. Dash and whitespace-free, upper case. */
    private static String normalise(String code) {
        return code.replace("-", "").replace(" ", "").toUpperCase();
    }
}
