package tech.cwvermaak.weldforge.service;

import tech.cwvermaak.weldforge.model.User;

/**
 * Rules shared by the tokens WeldForge mails to a person: email verification
 * and password reset (including admin-issued and invite resets).
 */
final class MailedTokens {

    private MailedTokens() {}

    /**
     * Whether a token mailed to {@code tokenAddress} may still act on
     * {@code user}. A token proves control of the mailbox it was sent to, and
     * both kinds end by marking the account's address verified, so it must
     * not complete once the account holds a different address.
     *
     * <p>A token with no address is refused: every token is written with one,
     * and V72 bound the ones outstanding when it ran.
     */
    static boolean stillAddressedTo(String tokenAddress, User user) {
        if (tokenAddress == null) return false;
        String current = user.getEmail();
        return current != null && current.trim().equalsIgnoreCase(tokenAddress.trim());
    }
}
