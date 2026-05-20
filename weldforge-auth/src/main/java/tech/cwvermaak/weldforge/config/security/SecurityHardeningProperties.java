package tech.cwvermaak.weldforge.config.security;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import tech.cwvermaak.weldforge.config.CorsProperties;
import tech.cwvermaak.weldforge.config.tenant.PublicHostProperties;
import tech.cwvermaak.weldforge.service.security.AccountLockoutProperties;
import tech.cwvermaak.weldforge.service.security.PasswordPolicyProperties;
import tech.cwvermaak.weldforge.service.security.RateLimitProperties;
import tech.cwvermaak.weldforge.service.security.RefreshTokenProperties;

/**
 * Registers every {@code @ConfigurationProperties} bean under
 * {@code app.*}. Keeps the configuration surface in one place so
 * operators can tune the whole security posture via environment variables
 * without touching code.
 */
@Configuration
@EnableConfigurationProperties({
        PasswordPolicyProperties.class,
        AccountLockoutProperties.class,
        RateLimitProperties.class,
        RefreshTokenProperties.class,
        CorsProperties.class,
        PublicHostProperties.class,
})
public class SecurityHardeningProperties {
}
