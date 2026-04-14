package tech.cwvermaak.intellisso.bdd;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.cucumber.java.en.Given;
import io.cucumber.java.en.Then;
import io.cucumber.java.en.When;
import org.mockito.ArgumentCaptor;
import tech.cwvermaak.intellisso.model.Tenant;
import tech.cwvermaak.intellisso.model.WebhookDelivery;
import tech.cwvermaak.intellisso.model.WebhookSubscription;
import tech.cwvermaak.intellisso.repository.WebhookDeliveryRepository;
import tech.cwvermaak.intellisso.repository.WebhookSubscriptionRepository;
import tech.cwvermaak.intellisso.service.webhook.WebhookHttpClient;
import tech.cwvermaak.intellisso.service.webhook.WebhookPublisher;
import tech.cwvermaak.intellisso.service.webhook.WebhookRetryScheduler;
import tech.cwvermaak.intellisso.service.webhook.WebhookSigner;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicLong;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Exercises {@link WebhookPublisher} with a fake {@link WebhookHttpClient}
 * so we can assert matching, signing and retry behaviour without a real
 * HTTP server.
 */
public class EpicFWebhooksSteps {

    private final TestWorld world;
    private final AtomicLong ids = new AtomicLong(51000);

    private WebhookSubscriptionRepository subscriptionRepository;
    private WebhookDeliveryRepository deliveryRepository;
    private FakeHttpClient httpClient;
    private WebhookPublisher publisher;
    private WebhookRetryScheduler scheduler;

    private final Map<Long, List<WebhookSubscription>> subsByTenant = new HashMap<>();
    private final Map<String, WebhookSubscription> subsByName = new HashMap<>();
    private final List<WebhookDelivery> deliveries = new ArrayList<>();

    public EpicFWebhooksSteps(TestWorld world) {
        this.world = world;
    }

    // ---- Wiring ----------------------------------------------------

    @SuppressWarnings("unchecked")
    private void ensureWired() {
        if (publisher != null) return;

        subscriptionRepository = mock(WebhookSubscriptionRepository.class);
        deliveryRepository = mock(WebhookDeliveryRepository.class);
        httpClient = new FakeHttpClient();

        when(subscriptionRepository.findByTenantIdAndEnabledTrue(anyLong())).thenAnswer(inv ->
                subsByTenant.getOrDefault(inv.<Long>getArgument(0), List.of()).stream()
                        .filter(WebhookSubscription::isEnabled)
                        .toList());
        when(deliveryRepository.save(any(WebhookDelivery.class))).thenAnswer(inv -> {
            WebhookDelivery d = inv.getArgument(0);
            if (d.getId() == null) {
                d.setId(ids.getAndIncrement());
                d.setCreatedAt(LocalDateTime.now());
                deliveries.add(d);
            }
            return d;
        });
        when(deliveryRepository.findTop100ByStatusAndNextAttemptAtLessThanEqualOrderByNextAttemptAtAsc(
                any(), any())).thenAnswer(inv -> {
            WebhookDelivery.Status status = inv.getArgument(0);
            LocalDateTime cutoff = inv.getArgument(1);
            return deliveries.stream()
                    .filter(d -> d.getStatus() == status)
                    .filter(d -> d.getNextAttemptAt() != null && !d.getNextAttemptAt().isAfter(cutoff))
                    .toList();
        });

        publisher = new WebhookPublisher(subscriptionRepository, deliveryRepository, httpClient, new ObjectMapper());
        scheduler = new WebhookRetryScheduler(deliveryRepository, publisher);
    }

    private Tenant tenant(String slug) {
        return world.tenants.computeIfAbsent(slug, s ->
                Tenant.builder().id(ids.getAndIncrement()).slug(s).name(s).enabled(true).build());
    }

    // ---- Fixtures --------------------------------------------------

    @Given("tenant {string} exists for webhook tests")
    public void tenantExists(String slug) {
        ensureWired();
        tenant(slug);
    }

    @Given("tenant {string} has webhook subscription {string} targeting {string}")
    public void tenantHasSub(String slug, String name, String url) {
        addSubscription(slug, name, url, null, 6);
    }

    @Given("tenant {string} has webhook subscription {string} targeting {string} filtering {string}")
    public void tenantHasFilteredSub(String slug, String name, String url, String filter) {
        addSubscription(slug, name, url, List.of(filter), 6);
    }

    @Given("tenant {string} has webhook subscription {string} targeting {string} with max attempts {int}")
    public void tenantHasCappedSub(String slug, String name, String url, int maxAttempts) {
        addSubscription(slug, name, url, null, maxAttempts);
    }

    private void addSubscription(String slug, String name, String url, List<String> filters, int maxAttempts) {
        Tenant t = tenant(slug);
        WebhookSubscription sub = WebhookSubscription.builder()
                .id(ids.getAndIncrement())
                .tenant(t)
                .name(name)
                .targetUrl(url)
                .secret("whsec_test_" + name)
                .eventFilters(filters)
                .enabled(true)
                .maxAttempts(maxAttempts)
                .build();
        subsByTenant.computeIfAbsent(t.getId(), k -> new ArrayList<>()).add(sub);
        subsByName.put(name, sub);
    }

    @Given("the HTTP client returns {int} for {string}")
    public void httpClientReturns(int code, String url) {
        httpClient.responsesByUrl.put(url, code);
    }

    // ---- Actions ---------------------------------------------------

    @When("webhook event {string} is published for tenant {string}")
    public void publish(String eventType, String slug) {
        publisher.publish(eventType, tenant(slug), Map.of("k", "v"));
    }

    @When("the retry scheduler runs")
    public void schedulerRuns() {
        // Force the backoff to "now" so the scheduler re-attempts immediately.
        for (WebhookDelivery d : deliveries) {
            if (d.getStatus() == WebhookDelivery.Status.PENDING && d.getNextAttemptAt() != null) {
                d.setNextAttemptAt(LocalDateTime.now().minusSeconds(1));
            }
        }
        // The scheduler only picks up rows with attempt_count >= 1 (see
        // WebhookRetryScheduler), so this mirrors the production flow where
        // the synchronous first attempt has already bumped the counter.
        scheduler.retryPending();
    }

    // ---- Assertions ------------------------------------------------

    @Then("a delivery was attempted to {string}")
    public void deliveryAttempted(String url) {
        assertThat(httpClient.calls).anyMatch(c -> c.url.equals(url));
    }

    @Then("no delivery was attempted to {string}")
    public void noDeliveryAttempted(String url) {
        assertThat(httpClient.calls).noneMatch(c -> c.url.equals(url));
    }

    @Then("the delivery carries an HMAC-SHA256 signature header")
    public void hmacSigPresent() {
        assertThat(httpClient.calls).isNotEmpty();
        FakeHttpClient.Call last = httpClient.calls.get(httpClient.calls.size() - 1);
        assertThat(last.signatureHeader).startsWith("t=");
        assertThat(last.signatureHeader).contains(",v1=");

        // Recompute independently and compare to prove the header is real,
        // not just a formatted placeholder.
        String[] parts = last.signatureHeader.split(",");
        long ts = Long.parseLong(parts[0].substring(2));
        String sent = parts[1].substring(3);
        WebhookSubscription sub = subsByName.values().stream()
                .filter(s -> s.getTargetUrl().equals(last.url))
                .findFirst().orElseThrow();
        String expected = WebhookSigner.sign(sub.getSecret(), ts, last.body);
        assertThat(sent).isEqualTo(expected);
    }

    @Then("the delivery was marked SUCCESS")
    public void markedSuccess() {
        assertThat(lastDelivery().getStatus()).isEqualTo(WebhookDelivery.Status.SUCCESS);
    }

    @Then("the delivery was marked PENDING")
    public void markedPending() {
        assertThat(lastDelivery().getStatus()).isEqualTo(WebhookDelivery.Status.PENDING);
    }

    @Then("the delivery was marked FAILED")
    public void markedFailed() {
        assertThat(lastDelivery().getStatus()).isEqualTo(WebhookDelivery.Status.FAILED);
    }

    @Then("the delivery was marked DEAD_LETTER")
    public void markedDead() {
        assertThat(lastDelivery().getStatus()).isEqualTo(WebhookDelivery.Status.DEAD_LETTER);
    }

    @Then("the delivery has next_attempt_at in the future")
    public void nextAttemptInFuture() {
        assertThat(lastDelivery().getNextAttemptAt()).isAfter(LocalDateTime.now().minusSeconds(1));
    }

    private WebhookDelivery lastDelivery() {
        assertThat(deliveries).isNotEmpty();
        return deliveries.get(deliveries.size() - 1);
    }

    // ---- Fake HTTP client -----------------------------------------

    static class FakeHttpClient implements WebhookHttpClient {
        static class Call {
            final String url;
            final String body;
            final String signatureHeader;
            Call(String url, String body, String sig) { this.url = url; this.body = body; this.signatureHeader = sig; }
        }
        final List<Call> calls = new ArrayList<>();
        final Map<String, Integer> responsesByUrl = new HashMap<>();

        @Override
        public Result post(String url, String body, String signatureHeader) {
            calls.add(new Call(url, body, signatureHeader));
            int code = responsesByUrl.getOrDefault(url, 200);
            return new Result(code, null);
        }
    }
}
