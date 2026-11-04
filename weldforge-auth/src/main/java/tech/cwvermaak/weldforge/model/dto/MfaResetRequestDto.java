package tech.cwvermaak.weldforge.model.dto;

import lombok.*;
import tech.cwvermaak.weldforge.model.MfaFactorType;

/**
 * Body of {@code POST /api/auth/mfa/reset}: the password, plus proof that the
 * caller still holds one of the factors they are asking to remove (B-AUTH-5,
 * F60).
 *
 * <p>The proof fields mirror {@link MfaVerifyRequestDto} and are flattened into
 * this body rather than nested, so the JSON stays one object and the existing
 * client only has to add a field. {@link #toProof()} hands them to
 * {@code MfaService.verifyChallenge}, which is the same code path that verifies
 * a factor mid-login — the reset cannot end up accepting a proof that a login
 * would reject.
 *
 * <p>{@code backupCode} is a first-class alternative, not a fallback: the whole
 * reason to reset is usually that the authenticator is gone.
 */
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class MfaResetRequestDto {

    /** Current password. Re-verified on every call; a failure feeds the account lockout. */
    private String password;

    /** Which factor is being presented as proof. Ignored when {@link #backupCode} is set. */
    private MfaFactorType type;

    /** TOTP or SMS code. */
    private String code;

    /** One-time backup code — the lost-authenticator path. */
    private String backupCode;

    /** WebAuthn assertion response JSON. */
    private String webauthnResponse;

    /** Challenge token, only for the WebAuthn ceremony. */
    private String challengeToken;

    /**
     * The proof half of this request, in the shape the MFA verifier expects.
     * Never null: a request carrying no proof at all becomes an empty proof,
     * which fails verification like any other wrong answer rather than
     * short-circuiting to a different error.
     */
    public MfaVerifyRequestDto toProof() {
        return MfaVerifyRequestDto.builder()
                .type(type)
                .code(code)
                .backupCode(backupCode)
                .webauthnResponse(webauthnResponse)
                .challengeToken(challengeToken)
                .build();
    }
}
