package tech.cwvermaak.intellisso.service.security;

import io.github.bucket4j.ConsumptionProbe;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import tech.cwvermaak.intellisso.service.security.RateLimitingService.Bucket4jEndpoint;

import static org.assertj.core.api.Assertions.assertThat;

class RateLimitingServiceTest {

    private RateLimitProperties props;
    private RateLimitingService service;

    @BeforeEach
    void setUp() {
        props = new RateLimitProperties();
        // Tight limits so the test doesn't have to hammer thousands of calls.
        props.setLoginCapacity(3);
        props.setLoginRefillMinutes(60);
        props.setMfaVerifyCapacity(2);
        props.setMfaVerifyRefillMinutes(60);
        props.setRegisterCapacity(1);
        props.setRegisterRefillMinutes(60);

        service = new RateLimitingService(props);
    }

    @Test
    @DisplayName("the login bucket allows up to capacity then starts rejecting")
    void loginBucket_capsAtConfiguredCapacity() {
        String key = "1.2.3.4";

        for (int i = 0; i < 3; i++) {
            ConsumptionProbe ok = service.tryConsume(Bucket4jEndpoint.LOGIN, key);
            assertThat(ok.isConsumed()).as("attempt %d should be allowed", i + 1).isTrue();
        }

        ConsumptionProbe over = service.tryConsume(Bucket4jEndpoint.LOGIN, key);
        assertThat(over.isConsumed()).isFalse();
        assertThat(over.getNanosToWaitForRefill()).isPositive();
    }

    @Test
    @DisplayName("separate IPs get independent buckets")
    void perIp_bucketsIndependent() {
        for (int i = 0; i < 3; i++) {
            assertThat(service.tryConsume(Bucket4jEndpoint.LOGIN, "1.1.1.1").isConsumed()).isTrue();
        }
        // 1.1.1.1 is now exhausted, but 2.2.2.2 should still be fine.
        assertThat(service.tryConsume(Bucket4jEndpoint.LOGIN, "2.2.2.2").isConsumed()).isTrue();
    }

    @Test
    @DisplayName("separate endpoints don't cross-pollute — exhausting login leaves register alone")
    void perEndpoint_bucketsIndependent() {
        String key = "1.2.3.4";
        for (int i = 0; i < 3; i++) {
            assertThat(service.tryConsume(Bucket4jEndpoint.LOGIN, key).isConsumed()).isTrue();
        }
        assertThat(service.tryConsume(Bucket4jEndpoint.LOGIN, key).isConsumed()).isFalse();
        assertThat(service.tryConsume(Bucket4jEndpoint.REGISTER, key).isConsumed()).isTrue();
        assertThat(service.tryConsume(Bucket4jEndpoint.MFA_VERIFY, key).isConsumed()).isTrue();
    }

    @Test
    @DisplayName("when disabled, every request is synthetically consumed")
    void disabled_alwaysAllows() {
        props.setEnabled(false);
        // Push far beyond the bucket capacity to prove the branch short-circuits.
        for (int i = 0; i < 50; i++) {
            assertThat(service.tryConsume(Bucket4jEndpoint.LOGIN, "1.2.3.4").isConsumed()).isTrue();
        }
    }
}
