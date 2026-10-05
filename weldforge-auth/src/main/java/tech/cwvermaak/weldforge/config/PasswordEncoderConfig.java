package tech.cwvermaak.weldforge.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * The password encoder, on its own.
 *
 * <p>It used to live in {@link SecurityConfig}. That made every bean needing
 * to hash a password depend on the class that builds the entire filter chain,
 * and the filter chain depends on much of the application — so adding an
 * authentication success handler that needed {@code AuthService} closed a
 * loop: SecurityConfig -> handler -> AuthService -> PasswordEncoder ->
 * SecurityConfig. Spring refused to start, and the message named a circular
 * reference rather than the cause.
 *
 * <p>Marking something {@code @Lazy} would have hidden it. A bcrypt encoder
 * has no business being defined beside the security filter chain, so it is
 * here instead and the cycle cannot form.
 */
@Configuration
public class PasswordEncoderConfig {

    @Bean
    public PasswordEncoder passwordEncoder() {
        // SEC-06: bcrypt cost factor 12. BCrypt encodes the cost into the
        // hash itself, so existing hashes at lower costs still verify
        // correctly — only new passwords are hashed at cost 12.
        return new BCryptPasswordEncoder(12);
    }
}
