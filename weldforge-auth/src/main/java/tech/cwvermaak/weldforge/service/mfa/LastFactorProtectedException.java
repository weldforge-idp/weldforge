package tech.cwvermaak.weldforge.service.mfa;

/**
 * Thrown when removing a factor would leave the account with no verified
 * second factor, i.e. would turn MFA off. Mapped to HTTP 409 by
 * {@code GlobalExceptionHandler}: the request is well-formed and the caller is
 * authorised, it conflicts with the account's current state.
 *
 * <p>The point is not that the operation is forbidden — a user may certainly
 * turn their own MFA off — but that it must go through
 * {@code POST /api/auth/mfa/reset}, which demands the password and a current
 * factor proof in the same request (B-AUTH-5, F60). {@code DELETE
 * /api/auth/mfa/factors/{id}} asks for neither, so left unguarded it is a
 * cheaper way to strip MFA than the endpoint built to require proof.
 *
 * <p>The message names the alternative, because a bare refusal here reads as a
 * bug to the person who is simply trying to turn MFA off.
 */
public class LastFactorProtectedException extends RuntimeException {

    public LastFactorProtectedException() {
        super("This is your last verified second factor, so removing it here would turn "
                + "MFA off without any proof that you still hold it. Use the MFA reset, "
                + "which asks for your password together with a code from an "
                + "authenticator or one of your backup codes.");
    }
}
