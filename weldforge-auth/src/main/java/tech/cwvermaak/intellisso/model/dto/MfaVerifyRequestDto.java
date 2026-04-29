package tech.cwvermaak.intellisso.model.dto;

import lombok.*;
import tech.cwvermaak.intellisso.model.MfaFactorType;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class MfaVerifyRequestDto {
    /** The mfa_challenge JWT returned by /api/auth/login. */
    private String challengeToken;

    /** Which factor the caller is presenting. */
    private MfaFactorType type;

    /** TOTP code — 6 digits. */
    private String code;

    /** One-time backup code — accepted as an alternative to {@link #code}. */
    private String backupCode;

    /** WebAuthn assertion response JSON. */
    private String webauthnResponse;
}
