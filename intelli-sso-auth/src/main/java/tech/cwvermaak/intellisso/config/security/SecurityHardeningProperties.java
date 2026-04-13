package tech.cwvermaak.intellisso.config.security;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import tech.cwvermaak.intellisso.config.CorsProperties;
import tech.cwvermaak.intellisso.service.security.AccountLockoutProperties;
import tech.cwvermaak.intellisso.service.security.PasswordPolicyProperties;
import tech.cwvermaak.intellisso.service.security.RateLimitProperties;
import tech.cwvermaak.intellisso.service.security.RefreshTokenProperties;

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
})
public class SecurityHardeningProperties {
}
