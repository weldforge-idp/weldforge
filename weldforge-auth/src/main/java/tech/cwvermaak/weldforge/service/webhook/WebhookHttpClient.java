package tech.cwvermaak.weldforge.service.webhook;

/**
 * Thin seam over the HTTP transport so tests can inject a fake client
 * without spinning up an embedded server. The production implementation
 * uses {@link java.net.http.HttpClient}; the BDD tests swap in a map-based
 * fake that records the body + signature for assertion.
 */
public interface WebhookHttpClient {

    /** Result of a single delivery attempt. */
    record Result(int statusCode, String error) {
        public boolean isSuccess() { return statusCode >= 200 && statusCode < 300; }
        public boolean isRetryable() {
            // 5xx and transport errors get retried; 4xx is a permanent fail.
            return error != null || statusCode >= 500;
        }
    }

    Result post(String url, String body, String signatureHeader);
}
