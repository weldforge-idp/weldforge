package tech.cwvermaak.weldforge.service.security;

/**
 * Screens a candidate password against a corpus of passwords known from data
 * breaches (NIST SP 800-63B §5.1.1.2, CONF-7.1).
 *
 * <p>Composition rules are the weak half of a password policy -- they push users
 * to {@code Password1!}, which satisfies every class and is in every breach
 * list. Screening is the strong half: it refuses exactly the passwords an
 * attacker tries first, whatever they look like.
 */
@FunctionalInterface
public interface BreachedPasswordScreen {

    enum Result {
        /** Present in the corpus: refuse it. */
        BREACHED,
        /** Not present. */
        CLEAN,
        /**
         * The corpus could not be consulted. Callers fail open: an outage of a
         * third-party corpus must not stop every registration and reset.
         */
        UNAVAILABLE
    }

    Result check(String password);

    /** Screening switched off, e.g. an air-gapped deployment or a unit test. */
    BreachedPasswordScreen DISABLED = password -> Result.CLEAN;
}
