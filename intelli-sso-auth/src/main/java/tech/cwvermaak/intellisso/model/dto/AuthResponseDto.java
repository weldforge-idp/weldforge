package tech.cwvermaak.intellisso.model.dto;

import lombok.*;
import tech.cwvermaak.intellisso.model.MfaFactorType;

import java.util.List;

/**
 * Unified response for the {@code /api/auth/login} endpoint. Either an
 * access token was issued (no MFA needed) or an MFA challenge is required
 * and the caller must complete the second step at {@code /api/auth/mfa/verify}.
 */
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class AuthResponseDto {
    /** Set when {@link #mfaRequired} is false. */
    private String token;
    private Long expiresIn;

    /** True if the caller must complete MFA before receiving an access token. */
    @Builder.Default
    private boolean mfaRequired = false;

    /** Opaque short-lived token to pass back on MFA verify. */
    private String mfaChallengeToken;

    /** Factor types the user has enrolled — drives which prompts to show. */
    private List<MfaFactorType> availableFactors;
}
