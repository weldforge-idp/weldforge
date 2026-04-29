package tech.cwvermaak.intellisso.service.webhook;

import io.github.resilience4j.circuitbreaker.CallNotPermittedException;
import io.github.resilience4j.circuitbreaker.CircuitBreaker;
import io.github.resilience4j.circuitbreaker.CircuitBreakerRegistry;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

/**
 * Production {@link WebhookHttpClient}. The HTTP call runs inside the
 * {@code webhook} circuit breaker (PRD AVL-04): once the failure rate
 * crosses the threshold the CB opens and subsequent calls fast-fail with
 * a tagged "circuit open" {@link Result}, which the publisher treats as
 * retryable so the delivery is rescheduled after the CB closes.
 */
@Component
@Slf4j
public class JdkWebhookHttpClient implements WebhookHttpClient {

    private static final String CB_NAME = "webhook";

    private final HttpClient client = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(5))
            .build();

    private final CircuitBreaker circuitBreaker;

    public JdkWebhookHttpClient(CircuitBreakerRegistry registry) {
        this.circuitBreaker = registry.circuitBreaker(CB_NAME);
    }

    @Override
    public Result post(String url, String body, String signatureHeader) {
        try {
            return circuitBreaker.executeSupplier(() -> doPost(url, body, signatureHeader));
        } catch (CallNotPermittedException cbOpen) {
            log.debug("Webhook CB open — fast-failing delivery to {}", url);
            return new Result(0, "circuit breaker open");
        } catch (WebhookHttpException e) {
            return new Result(0, e.getMessage());
        }
    }

    private Result doPost(String url, String body, String signatureHeader) {
        try {
            HttpRequest req = HttpRequest.newBuilder()
                    .uri(URI.create(url))
                    .timeout(Duration.ofSeconds(10))
                    .header("Content-Type", "application/json")
                    .header(WebhookSigner.HEADER, signatureHeader)
                    .POST(HttpRequest.BodyPublishers.ofString(body))
                    .build();
            HttpResponse<String> resp = client.send(req, HttpResponse.BodyHandlers.ofString());
            // 5xx responses count as failures against the CB so we learn
            // about a struggling receiver without waiting for a timeout.
            if (resp.statusCode() >= 500) {
                throw new WebhookHttpException("HTTP " + resp.statusCode());
            }
            return new Result(resp.statusCode(), null);
        } catch (WebhookHttpException rethrow) {
            throw rethrow;
        } catch (Exception e) {
            throw new WebhookHttpException(e.getMessage());
        }
    }

    private static class WebhookHttpException extends RuntimeException {
        WebhookHttpException(String message) { super(message); }
    }
}
