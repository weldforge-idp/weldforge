package tech.cwvermaak.weldforge.config.security;

import io.micrometer.core.instrument.MeterRegistry;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import tech.cwvermaak.weldforge.service.security.BreachedPasswordScreen;
import tech.cwvermaak.weldforge.service.security.PasswordPolicyProperties;
import tech.cwvermaak.weldforge.service.security.PwnedPasswordsScreen;

/** Wires breached-password screening (CONF-7.1) from {@code app.security.password.breach-check}. */
@Configuration
@Slf4j
public class BreachedPasswordScreenConfig {

    @Bean
    public BreachedPasswordScreen breachedPasswordScreen(PasswordPolicyProperties properties,
                                                         MeterRegistry meterRegistry) {
        PasswordPolicyProperties.BreachCheck cfg = properties.getBreachCheck();
        if (!cfg.isEnabled()) {
            log.warn("Breached-password screening is DISABLED (app.security.password.breach-check.enabled=false); "
                    + "passwords from known breaches will be accepted");
            return BreachedPasswordScreen.DISABLED;
        }
        return new PwnedPasswordsScreen(cfg.getRangeUrl(), cfg.getTimeout(), meterRegistry);
    }
}
