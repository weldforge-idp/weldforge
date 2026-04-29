package tech.cwvermaak.intellisso.config.scim;

import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Spring Boot would otherwise auto-register {@link ScimAuthenticationFilter}
 * at the outer servlet level — we want it inside the Security chain
 * (added explicitly in {@code SecurityConfig}) so the order relative to
 * the JWT filter and tenant resolver is deterministic.
 */
@Configuration
public class ScimSecurityConfig {

    @Bean
    public FilterRegistrationBean<ScimAuthenticationFilter> scimAuthenticationFilterRegistration(
            ScimAuthenticationFilter filter) {
        FilterRegistrationBean<ScimAuthenticationFilter> registration = new FilterRegistrationBean<>(filter);
        registration.setEnabled(false);
        return registration;
    }
}
