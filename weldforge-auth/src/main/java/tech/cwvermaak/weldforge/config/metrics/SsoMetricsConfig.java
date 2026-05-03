package tech.cwvermaak.weldforge.config.metrics;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Registers custom SSO metrics with Micrometer so they are exported to
 * Prometheus via {@code /actuator/prometheus}. Each service increments
 * these counters with tenant-specific tags at call time.
 *
 * Counters use a {@code sso.} prefix to namespace them away from
 * Spring Boot's built-in metrics.
 */
@Configuration
public class SsoMetricsConfig {

    @Bean
    public Counter loginSuccessCounter(MeterRegistry registry) {
        return Counter.builder("sso.auth.login")
                .description("Login attempts")
                .tag("outcome", "success")
                .register(registry);
    }

    @Bean
    public Counter loginFailureCounter(MeterRegistry registry) {
        return Counter.builder("sso.auth.login")
                .description("Login attempts")
                .tag("outcome", "failure")
                .register(registry);
    }

    @Bean
    public Counter tokenIssuedCounter(MeterRegistry registry) {
        return Counter.builder("sso.token.issued")
                .description("OIDC tokens issued")
                .register(registry);
    }

    @Bean
    public Counter scimOperationsCounter(MeterRegistry registry) {
        return Counter.builder("sso.scim.operations")
                .description("SCIM provisioning operations")
                .register(registry);
    }
}
