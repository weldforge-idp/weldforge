package tech.cwvermaak.weldforge.service.security;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

@Getter
@Setter
@ConfigurationProperties(prefix = "app.security.lockout")
public class AccountLockoutProperties {

    /** Lock after this many consecutive failed logins. */
    private int maxAttempts = 5;

    /** Minutes the account stays locked once the threshold is tripped. */
    private int lockMinutes = 15;
}
