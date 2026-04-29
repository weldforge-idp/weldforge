package tech.cwvermaak.intellisso.config.logging;

import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Spring Boot eagerly registers every {@link jakarta.servlet.Filter} bean at
 * the servlet container level. We want the MDC filter to live *inside* the
 * Spring Security chain (so the JWT filter has already populated the
 * authentication and tenant context by the time MDC is enriched), not at the
 * outer servlet level. Returning a disabled {@link FilterRegistrationBean}
 * suppresses auto-registration — {@code SecurityConfig} then installs the
 * filter manually via {@code addFilterAfter(..., JwtAuthenticationFilter.class)}.
 */
@Configuration
public class LoggingConfig {

    @Bean
    public FilterRegistrationBean<MdcEnrichmentFilter> mdcEnrichmentFilterRegistration(
            MdcEnrichmentFilter filter) {
        FilterRegistrationBean<MdcEnrichmentFilter> registration = new FilterRegistrationBean<>(filter);
        registration.setEnabled(false);
        return registration;
    }
}
