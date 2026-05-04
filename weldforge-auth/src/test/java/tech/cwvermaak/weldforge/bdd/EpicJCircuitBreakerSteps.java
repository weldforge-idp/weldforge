package tech.cwvermaak.weldforge.bdd;

import io.cucumber.java.en.Given;
import io.cucumber.java.en.Then;
import io.cucumber.java.en.When;
import io.github.resilience4j.circuitbreaker.CallNotPermittedException;
import io.github.resilience4j.circuitbreaker.CircuitBreaker;
import io.github.resilience4j.circuitbreaker.CircuitBreakerConfig;
import io.github.resilience4j.circuitbreaker.CircuitBreakerRegistry;
import tech.cwvermaak.weldforge.service.webhook.WebhookHttpClient;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Exercises the circuit breaker pattern (PRD AVL-04) the production
 * {@code JdkWebhookHttpClient} uses. A fake HTTP transport is run inside
 * a real {@link CircuitBreakerRegistry} configured the same way as the
 * one in {@code application.yml}, so state transitions here are faithful
 * to what the production wiring will see.
 */
public class EpicJCircuitBreakerSteps {

    private CircuitBreakerRegistry registry;
    private CircuitBreaker breaker;
    private CbWrappedClient client;
    private final FakeTransport transport = new FakeTransport();
    private final List<WebhookHttpClient.Result> results = new ArrayList<>();

    @Given("a circuit breaker {string} with failure threshold {int}% and window {int}")
    public void circuitBreakerWith(String name, int failurePct, int window) {
        CircuitBreakerConfig config = CircuitBreakerConfig.custom()
                .slidingWindowType(CircuitBreakerConfig.SlidingWindowType.COUNT_BASED)
                .slidingWindowSize(window)
                .minimumNumberOfCalls(window)
                .failureRateThreshold((float) failurePct)
                .waitDurationInOpenState(Duration.ofSeconds(30))
                .permittedNumberOfCallsInHalfOpenState(3)
                .automaticTransitionFromOpenToHalfOpenEnabled(false)
                .build();
        registry = CircuitBreakerRegistry.of(config);
        breaker = registry.circuitBreaker(name);
    }

    @Given("the webhook HTTP client is wrapped with the {string} circuit breaker")
    public void clientWrapped(String name) {
        client = new CbWrappedClient(breaker, transport);
    }

    @Given("the underlying HTTP client always succeeds")
    public void alwaysSucceeds() {
        transport.mode = FakeTransport.Mode.SUCCESS;
    }

    @Given("the underlying HTTP client always fails with {int}")
    public void alwaysFailsWith(int status) {
        transport.mode = FakeTransport.Mode.FAIL_5XX;
        transport.statusCode = status;
    }

    @Given("the circuit breaker is transitioned to half-open")
    public void transitionHalfOpen() {
        breaker.transitionToHalfOpenState();
    }

    @When("the webhook client posts {int} times")
    public void postNTimes(int n) {
        for (int i = 0; i < n; i++) {
            results.add(client.post("https://example.test/hook", "{}", "sig"));
        }
    }

    @When("the webhook client posts {int} more times")
    public void postNMoreTimes(int n) {
        postNTimes(n);
    }

    @Then("the circuit breaker state is {string}")
    public void stateIs(String expected) {
        assertThat(breaker.getState().name()).isEqualTo(expected);
    }

    @Then("{int} underlying calls were made")
    public void underlyingCallCount(int n) {
        assertThat(transport.callCount).isEqualTo(n);
    }

    @Then("only {int} underlying calls were made")
    public void onlyNCalls(int n) {
        assertThat(transport.callCount).isEqualTo(n);
    }

    @Then("the last {int} results all carry a {string} error")
    public void lastResultsCarryError(int n, String errorFragment) {
        List<WebhookHttpClient.Result> tail = results.subList(results.size() - n, results.size());
        assertThat(tail).allMatch(r -> r.error() != null && r.error().contains(errorFragment));
    }

    // ---- Helpers ---------------------------------------------------

    /**
     * Mirrors {@code JdkWebhookHttpClient.post} exactly: run the call
     * through the CB, translate CallNotPermitted into a Result with an
     * error marker, turn 5xx into failures so the CB counts them.
     */
    static class CbWrappedClient implements WebhookHttpClient {
        private final CircuitBreaker cb;
        private final FakeTransport transport;

        CbWrappedClient(CircuitBreaker cb, FakeTransport transport) {
            this.cb = cb;
            this.transport = transport;
        }

        @Override
        public Result post(String url, String body, String signatureHeader) {
            try {
                return cb.executeSupplier(() -> {
                    Result r = transport.post(url, body, signatureHeader);
                    if (r.statusCode() >= 500) {
                        throw new RuntimeException("HTTP " + r.statusCode());
                    }
                    return r;
                });
            } catch (CallNotPermittedException cbOpen) {
                return new Result(0, "circuit breaker open");
            } catch (RuntimeException e) {
                return new Result(0, e.getMessage());
            }
        }
    }

    static class FakeTransport {
        enum Mode { SUCCESS, FAIL_5XX }
        Mode mode = Mode.SUCCESS;
        int statusCode = 200;
        int callCount;

        WebhookHttpClient.Result post(String url, String body, String sig) {
            callCount++;
            return switch (mode) {
                case SUCCESS -> new WebhookHttpClient.Result(200, null);
                case FAIL_5XX -> new WebhookHttpClient.Result(statusCode, null);
            };
        }
    }
}
