package tech.cwvermaak.weldforge.service.security;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

@Getter
@Setter
@ConfigurationProperties(prefix = "app.security.rate-limit")
public class RateLimitProperties {

    private boolean enabled = true;

    /** Token bucket capacity per IP for login attempts. */
    private int loginCapacity = 10;

    /** Refill period in minutes for the login bucket. */
    private int loginRefillMinutes = 15;

    /** Bucket capacity per IP for MFA verify attempts. */
    private int mfaVerifyCapacity = 15;

    /** Refill period in minutes for the MFA bucket. */
    private int mfaVerifyRefillMinutes = 15;

    /** Bucket capacity per IP for registration attempts. */
    private int registerCapacity = 5;

    private int registerRefillMinutes = 60;
}
