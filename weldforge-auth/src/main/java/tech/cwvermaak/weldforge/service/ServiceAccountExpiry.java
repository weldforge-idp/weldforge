package tech.cwvermaak.weldforge.service;

import java.time.LocalDateTime;

/**
 * Turns a requested lifetime — so many days and hours, or zero for
 * indefinite — into the absolute instant stored on a service account.
 *
 * <p>Callers ask in the units they think in. A token is issued "for ninety
 * days", not "until 2026-12-29T09:31:04". Making the API take an absolute
 * timestamp pushed that arithmetic onto every caller, and the portal simply
 * never did it: every token created through the UI was indefinite, because
 * indefinite was the only thing the screen could express.
 *
 * <p><strong>Zero means indefinite, and that is the whole point of having a
 * sentinel.</strong> Without one, "no expiry" and "don't change the expiry"
 * are both {@code null} on the wire, so an account that expires can never be
 * set back to permanent — the update path reads the null as "leave alone".
 * That is the same trap that made {@code webOrigins} unclearable on an OIDC
 * client until an explicit empty list was given meaning.
 */
public final class ServiceAccountExpiry {

    /**
     * The longest lifetime that can be requested, beyond which the caller
     * almost certainly meant something else.
     *
     * <p>Ten years is not a security boundary — indefinite is still allowed,
     * explicitly. It catches the transposition: hours typed into the days
     * field, or a millisecond value pasted where a day count belongs. A
     * token quietly issued for 87,600 days reads as "expires" in every
     * listing while being permanent in practice, which is worse than being
     * honestly indefinite.
     */
    public static final int MAX_DAYS = 3650;

    private ServiceAccountExpiry() {
    }

    /** What the caller asked for, distinguishing "nothing" from "never". */
    public enum Intent {
        /** Neither field supplied: leave whatever is already there. */
        UNCHANGED,
        /** Explicit zero: the token never expires. */
        INDEFINITE,
        /** A positive duration was given. */
        ABSOLUTE
    }

    /** The resolved outcome: an intent, and the instant when it is ABSOLUTE. */
    public record Resolved(Intent intent, LocalDateTime expiresAt) {

        /** The value to store, given what the account currently holds. */
        public LocalDateTime applyTo(LocalDateTime current) {
            return switch (intent) {
                case UNCHANGED  -> current;
                case INDEFINITE -> null;
                case ABSOLUTE   -> expiresAt;
            };
        }

        /** How this reads in an audit entry. */
        public String describe() {
            return switch (intent) {
                case UNCHANGED  -> "unchanged";
                case INDEFINITE -> "indefinite";
                case ABSOLUTE   -> expiresAt.toString();
            };
        }
    }

    /**
     * Resolve a requested lifetime.
     *
     * @param days  whole days, or null when not supplied
     * @param hours additional hours, or null when not supplied
     * @param now   the clock, passed in so this is testable
     * @throws IllegalArgumentException on a negative or implausible duration
     */
    public static Resolved resolve(Integer days, Integer hours, LocalDateTime now) {
        if (days == null && hours == null) {
            return new Resolved(Intent.UNCHANGED, null);
        }

        int d = days  == null ? 0 : days;
        int h = hours == null ? 0 : hours;

        if (d < 0 || h < 0) {
            throw new IllegalArgumentException(
                    "Token lifetime cannot be negative. Use 0 for a token that never expires.");
        }
        // Explicit zero, in either field or both, is the documented way to say
        // "never expires". It is only ambiguous if you allow one field to be
        // zero and the other absent to mean something different -- so it does
        // not: any supplied zero total is indefinite.
        if (d == 0 && h == 0) {
            return new Resolved(Intent.INDEFINITE, null);
        }

        // Compare in hours so 3650 days and 87,600 hours are refused alike;
        // long arithmetic because int hours would overflow around 245,000 days.
        long totalHours = (long) d * 24L + (long) h;
        if (totalHours > (long) MAX_DAYS * 24L) {
            throw new IllegalArgumentException(
                    "Token lifetime cannot exceed " + MAX_DAYS + " days. "
                    + "Use 0 for a token that never expires.");
        }

        return new Resolved(Intent.ABSOLUTE, now.plusDays(d).plusHours(h));
    }
}
