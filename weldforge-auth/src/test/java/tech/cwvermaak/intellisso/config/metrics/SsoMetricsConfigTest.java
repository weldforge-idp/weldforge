package tech.cwvermaak.intellisso.config.metrics;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class SsoMetricsConfigTest {

    private SimpleMeterRegistry registry;
    private SsoMetricsConfig config;

    @BeforeEach
    void setUp() {
        registry = new SimpleMeterRegistry();
        config = new SsoMetricsConfig();
    }

    @Test
    void loginSuccessCounterIsRegistered() {
        Counter counter = config.loginSuccessCounter(registry);
        assertThat(counter).isNotNull();
        counter.increment();
        assertThat(counter.count()).isEqualTo(1.0);
        assertThat(counter.getId().getName()).isEqualTo("sso.auth.login");
        assertThat(counter.getId().getTag("outcome")).isEqualTo("success");
    }

    @Test
    void loginFailureCounterIsRegistered() {
        Counter counter = config.loginFailureCounter(registry);
        assertThat(counter).isNotNull();
        counter.increment();
        assertThat(counter.count()).isEqualTo(1.0);
        assertThat(counter.getId().getTag("outcome")).isEqualTo("failure");
    }

    @Test
    void tokenIssuedCounterIsRegistered() {
        Counter counter = config.tokenIssuedCounter(registry);
        assertThat(counter).isNotNull();
        assertThat(counter.getId().getName()).isEqualTo("sso.token.issued");
    }

    @Test
    void scimOperationsCounterIsRegistered() {
        Counter counter = config.scimOperationsCounter(registry);
        assertThat(counter).isNotNull();
        assertThat(counter.getId().getName()).isEqualTo("sso.scim.operations");
    }
}
