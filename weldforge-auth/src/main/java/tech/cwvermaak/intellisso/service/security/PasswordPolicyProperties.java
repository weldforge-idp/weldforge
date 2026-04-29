package tech.cwvermaak.intellisso.service.security;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Configurable rules for {@link PasswordPolicyService}. Defaults are a
 * reasonable baseline for a B2B identity product — tenants or deployments
 * that need stricter rules can override via {@code app.security.password.*}.
 */
@Getter
@Setter
@ConfigurationProperties(prefix = "app.security.password")
public class PasswordPolicyProperties {

    /** Minimum accepted length. Users that are well under this are almost always brute-forceable. */
    private int minLength = 10;

    /** Hard cap — bcrypt only hashes the first 72 bytes, so we refuse longer inputs to avoid silent truncation DoS. */
    private int maxLength = 72;

    private boolean requireUppercase = true;
    private boolean requireLowercase = true;
    private boolean requireDigit     = true;
    private boolean requireSymbol    = true;
}
