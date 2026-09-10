package tech.cwvermaak.weldforge.service.security;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;

/**
 * Configurable rules for {@link PasswordPolicyService}, via
 * {@code app.security.password.*}.
 *
 * <p>The defaults follow NIST SP 800-63B §5.1.1.2 (CONF-7.1): length and
 * breach screening, no composition rules. Composition rules are what produce
 * {@code Password1!} -- every class satisfied, and in every breach list -- so
 * 800-63B says verifiers SHALL NOT impose them. They remain available for a
 * deployment whose own policy still demands them; see
 * {@code docs/security/configuration-reference.md}.
 */
@Getter
@Setter
@ConfigurationProperties(prefix = "app.security.password")
public class PasswordPolicyProperties {

    /**
     * Minimum accepted length. 800-63B's floor is 8; 12 is where a passphrase
     * of a few ordinary words lands, and it costs a user nothing once they are
     * not also asked for a symbol.
     */
    private int minLength = 12;

    /** Hard cap — bcrypt only hashes the first 72 bytes, so we refuse longer inputs to avoid silent truncation DoS. */
    private int maxLength = 72;

    private boolean requireUppercase = false;
    private boolean requireLowercase = false;
    private boolean requireDigit     = false;
    private boolean requireSymbol    = false;

    private BreachCheck breachCheck = new BreachCheck();

    /** Screening against a breached-password corpus (800-63B §5.1.1.2). */
    @Getter
    @Setter
    public static class BreachCheck {
        /** Off only for air-gapped deployments; the check fails open when the corpus is unreachable. */
        private boolean enabled = true;
        /** k-anonymity range endpoint; the five-character SHA-1 prefix is appended. */
        private String rangeUrl = PwnedPasswordsScreen.DEFAULT_RANGE_URL;
        /** Connect and read timeout. Registration waits at most this long before failing open. */
        private Duration timeout = Duration.ofSeconds(2);
    }
}
