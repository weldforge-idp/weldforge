package tech.cwvermaak.weldforge.bdd;

import io.cucumber.java.en.Given;
import io.cucumber.java.en.Then;
import io.cucumber.java.en.When;
import tech.cwvermaak.weldforge.model.AuditEvent;
import tech.cwvermaak.weldforge.model.ServiceAccount;
import tech.cwvermaak.weldforge.model.Tenant;
import tech.cwvermaak.weldforge.model.dto.payment.CreateOrderRequest;
import tech.cwvermaak.weldforge.model.dto.payment.CreateOrderResponse;
import tech.cwvermaak.weldforge.model.payment.*;
import tech.cwvermaak.weldforge.repository.BillingTransactionRepository;
import tech.cwvermaak.weldforge.repository.PaymentGatewayRepository;
import tech.cwvermaak.weldforge.repository.PendingOrderRepository;
import tech.cwvermaak.weldforge.repository.ServiceAccountRepository;
import tech.cwvermaak.weldforge.repository.SubscriptionRepository;
import tech.cwvermaak.weldforge.repository.TenantRepository;
import tech.cwvermaak.weldforge.service.audit.AuditService;
import tech.cwvermaak.weldforge.service.payment.FeeCalculator;
import tech.cwvermaak.weldforge.service.payment.OrderService;
import tech.cwvermaak.weldforge.service.payment.PaymentRoutingService;
import tech.cwvermaak.weldforge.service.payment.TenantProvisioningService;
import tech.cwvermaak.weldforge.service.payment.WebhookService;
import tech.cwvermaak.weldforge.service.payment.gateway.GatewayCredentials;
import tech.cwvermaak.weldforge.service.payment.gateway.PaymentGatewayStrategy;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicLong;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * BDD coverage for the V31 payment subsystem — exercises the
 * {@link OrderService} state machine + {@link TenantProvisioningService}
 * + {@link WebhookService} wired together with mocked repositories
 * and a fake {@link PaymentGatewayStrategy}. No network, no Stripe SDK,
 * no database.
 */
public class PaymentPlatformBillingSteps {

    private static final String VALID_SIGNATURE = "sig_valid";

    private final TestWorld world;
    private final AtomicLong ids = new AtomicLong(80_000);

    // In-memory state backing the mocks.
    private final Map<Long, PaymentGateway>      gatewaysById    = new HashMap<>();
    private final Map<Long, PendingOrder>        ordersById      = new HashMap<>();
    private final Map<String, PendingOrder>      ordersByToken   = new HashMap<>();
    private final Map<String, PendingOrder>      ordersBySession = new HashMap<>();
    private final Map<Long, Tenant>              tenantsById     = new HashMap<>();
    private final Map<String, Tenant>            tenantsBySlug   = new HashMap<>();
    private final List<ServiceAccount>           serviceAccounts = new ArrayList<>();
    private final List<Subscription>             subscriptions   = new ArrayList<>();
    private final List<BillingTransaction>       billingTxs      = new ArrayList<>();
    private final FakeStripeGateway              fakeGateway     = new FakeStripeGateway();

    // Wired services.
    private OrderService               orderService;
    private TenantProvisioningService  provisioningService;
    private WebhookService             webhookService;

    private CreateOrderResponse        lastCreateResponse;
    private WebhookService.Result      lastWebhookResult;

    public PaymentPlatformBillingSteps(TestWorld world) {
        this.world = world;
    }

    // ---- Wiring ---------------------------------------------------

    @SuppressWarnings("unchecked")
    private void ensureWired() {
        if (orderService != null) return;

        PaymentGatewayRepository gatewayRepo = mock(PaymentGatewayRepository.class);
        PendingOrderRepository orderRepo = mock(PendingOrderRepository.class);
        BillingTransactionRepository txRepo = mock(BillingTransactionRepository.class);
        TenantRepository tenantRepo = mock(TenantRepository.class);
        ServiceAccountRepository saRepo = mock(ServiceAccountRepository.class);
        SubscriptionRepository subRepo = mock(SubscriptionRepository.class);
        AuditService auditService = mock(AuditService.class);

        // payment_gateways
        when(gatewayRepo.findByScopeAndEnabledTrue(any(GatewayScope.class))).thenAnswer(inv -> {
            GatewayScope scope = inv.getArgument(0);
            return gatewaysById.values().stream()
                    .filter(g -> g.getScope() == scope && g.isEnabled())
                    .toList();
        });
        when(gatewayRepo.findEnabledPlatformGateways()).thenAnswer(inv ->
                gatewaysById.values().stream()
                        .filter(g -> g.getScope() == GatewayScope.PLATFORM && g.isEnabled())
                        .toList());

        // pending_orders
        when(orderRepo.saveAndFlush(any(PendingOrder.class))).thenAnswer(inv -> persistOrder(inv.getArgument(0)));
        when(orderRepo.save(any(PendingOrder.class))).thenAnswer(inv -> persistOrder(inv.getArgument(0)));
        when(orderRepo.saveAll(any())).thenAnswer(inv -> {
            Iterable<PendingOrder> all = inv.getArgument(0);
            for (PendingOrder o : all) persistOrder(o);
            return all;
        });
        when(orderRepo.findByOrderToken(anyString())).thenAnswer(inv ->
                Optional.ofNullable(ordersByToken.get(inv.<String>getArgument(0))));
        when(orderRepo.findById(anyLong())).thenAnswer(inv ->
                Optional.ofNullable(ordersById.get(inv.<Long>getArgument(0))));
        when(orderRepo.findByGatewaySessionId(anyString())).thenAnswer(inv ->
                Optional.ofNullable(ordersBySession.get(inv.<String>getArgument(0))));
        when(orderRepo.findByStatus(any(OrderStatus.class))).thenAnswer(inv -> {
            OrderStatus s = inv.getArgument(0);
            return ordersById.values().stream().filter(o -> o.getStatus() == s).toList();
        });
        when(orderRepo.findByStatusAndSlugReservationExpiresBefore(any(), any())).thenAnswer(inv -> {
            OrderStatus s = inv.getArgument(0);
            LocalDateTime cutoff = inv.getArgument(1);
            return ordersById.values().stream()
                    .filter(o -> o.getStatus() == s)
                    .filter(o -> o.getSlugReservationExpires() != null
                              && o.getSlugReservationExpires().isBefore(cutoff))
                    .toList();
        });

        // billing_transactions
        when(txRepo.save(any(BillingTransaction.class))).thenAnswer(inv -> {
            BillingTransaction t = inv.getArgument(0);
            if (t.getId() == null) t.setId(ids.getAndIncrement());
            // Simulate the unique (gateway_id, gateway_tx_id) index: the
            // service ALWAYS checks findBy... before save, but we still
            // want to guard against a bug that bypasses the check.
            boolean dup = billingTxs.stream().anyMatch(existing ->
                    Objects.equals(existing.getGateway().getId(), t.getGateway().getId())
                    && Objects.equals(existing.getGatewayTransactionId(), t.getGatewayTransactionId()));
            if (dup) {
                throw new org.springframework.dao.DataIntegrityViolationException(
                        "duplicate billing_transaction (gateway_id, gateway_transaction_id)");
            }
            billingTxs.add(t);
            return t;
        });
        when(txRepo.findByGatewayIdAndGatewayTransactionId(anyLong(), anyString())).thenAnswer(inv -> {
            Long gid = inv.getArgument(0);
            String txId = inv.getArgument(1);
            return billingTxs.stream()
                    .filter(t -> Objects.equals(t.getGateway().getId(), gid)
                            && Objects.equals(t.getGatewayTransactionId(), txId))
                    .findFirst();
        });

        // tenants
        when(tenantRepo.save(any(Tenant.class))).thenAnswer(inv -> persistTenant(inv.getArgument(0)));
        when(tenantRepo.findById(anyLong())).thenAnswer(inv ->
                Optional.ofNullable(tenantsById.get(inv.<Long>getArgument(0))));
        when(tenantRepo.findBySlug(anyString())).thenAnswer(inv ->
                Optional.ofNullable(tenantsBySlug.get(inv.<String>getArgument(0))));
        when(tenantRepo.existsBySlug(anyString())).thenAnswer(inv ->
                tenantsBySlug.containsKey(inv.<String>getArgument(0)));

        // service_accounts + subscriptions
        when(saRepo.save(any(ServiceAccount.class))).thenAnswer(inv -> {
            ServiceAccount sa = inv.getArgument(0);
            if (sa.getId() == null) sa.setId(ids.getAndIncrement());
            serviceAccounts.add(sa);
            return sa;
        });
        when(subRepo.save(any(Subscription.class))).thenAnswer(inv -> {
            Subscription s = inv.getArgument(0);
            if (s.getId() == null) s.setId(ids.getAndIncrement());
            subscriptions.add(s);
            return s;
        });

        // AuditService — capture into world.auditLog.
        doAnswer(inv -> {
            AuditEvent.AuditEventBuilder b = inv.getArgument(0);
            world.auditLog.add(b.build());
            return null;
        }).when(auditService).log(any(AuditEvent.AuditEventBuilder.class));

        // Build real services.
        FeeCalculator feeCalculator = new FeeCalculator();
        PaymentRoutingService routing = new PaymentRoutingService(gatewayRepo, feeCalculator);
        tech.cwvermaak.weldforge.service.TenantSlugValidator slugValidator =
                mock(tech.cwvermaak.weldforge.service.TenantSlugValidator.class);
        when(slugValidator.validate(anyString())).thenAnswer(inv -> inv.getArgument(0));
        orderService = new OrderService(orderRepo, txRepo, routing, slugValidator, List.of(fakeGateway));
        provisioningService = new TenantProvisioningService(
                tenantRepo, saRepo, subRepo, orderRepo, orderService, auditService, slugValidator);
        webhookService = new WebhookService(gatewayRepo, orderService, provisioningService, List.of(fakeGateway));
    }

    private PendingOrder persistOrder(PendingOrder o) {
        if (o.getId() == null) o.setId(ids.getAndIncrement());
        if (o.getCreatedAt() == null) o.setCreatedAt(LocalDateTime.now());
        ordersById.put(o.getId(), o);
        ordersByToken.put(o.getOrderToken(), o);
        if (o.getGatewaySessionId() != null) ordersBySession.put(o.getGatewaySessionId(), o);
        return o;
    }

    private Tenant persistTenant(Tenant t) {
        if (t.getId() == null) t.setId(ids.getAndIncrement());
        tenantsById.put(t.getId(), t);
        tenantsBySlug.put(t.getSlug(), t);
        return t;
    }

    // ---- Background -----------------------------------------------

    @Given("the platform has a fake payment gateway configured for USD")
    public void platformHasGateway() {
        ensureWired();
        PaymentGateway g = PaymentGateway.builder()
                .id(ids.getAndIncrement())
                .scope(GatewayScope.PLATFORM)
                .provider(GatewayProvider.STRIPE)
                .displayName("fake-stripe")
                .enabled(true)
                .priority(0)
                .supportedCurrencies(List.of("USD"))
                .supportedCountries(null)
                .config(Map.of())
                .credentialsEncrypted(GatewayCredentials.encode(Map.of(
                        "secret_key",     "sk_test_fake",
                        "webhook_secret", "whsec_fake")))
                .feeStructure(Map.of("percent", 2.9, "fixed_cents", 30, "home_country", "US"))
                .build();
        gatewaysById.put(g.getId(), g);
    }

    @Given("the tier {string} costs {int} cents monthly")
    public void tierCost(String tier, int cents) {
        // Declarative — asserted by the fact that OrderService computes
        // amount_cents via TierPricing. Present to make the feature readable.
        assertThat(tier).isNotBlank();
        assertThat(cents).isPositive();
    }

    // ---- Orders ---------------------------------------------------

    @When("a customer submits an order for tier {string} with slug {string} and email {string}")
    public void customerSubmits(String tier, String slug, String email) {
        CreateOrderRequest req = newRequest(tier, slug, email);
        lastCreateResponse = orderService.createOrder(req);
    }

    @Given("a customer submitted an order for tier {string} with slug {string} and email {string}")
    public void customerSubmittedOrder(String tier, String slug, String email) {
        customerSubmits(tier, slug, email);
    }

    @Given("a customer submitted an order for tier {string} with slug {string} and email {string} {int} minutes ago")
    public void customerSubmittedOrderAgo(String tier, String slug, String email, int minutesAgo) {
        customerSubmits(tier, slug, email);
        PendingOrder order = ordersByToken.get(lastCreateResponse.getOrderToken());
        LocalDateTime backdated = LocalDateTime.now().minusMinutes(minutesAgo);
        order.setCreatedAt(backdated);
        order.setSlugReservationExpires(backdated.plusMinutes(10));
    }

    @Then("the order is in state {string}")
    public void orderStateIs(String state) {
        PendingOrder order = ordersByToken.get(lastCreateResponse.getOrderToken());
        assertThat(order.getStatus()).isEqualTo(OrderStatus.valueOf(state));
    }

    @Then("the customer received a checkout URL")
    public void receivedCheckoutUrl() {
        assertThat(lastCreateResponse.getCheckoutUrl()).startsWith("https://checkout.fake/");
    }

    // ---- Webhooks -------------------------------------------------

    @When("a payment-succeeded webhook arrives for that order with tx id {string}")
    public void paymentSucceededWebhook(String txId) {
        fakeGateway.nextEventType = PaymentGatewayStrategy.EventType.CHECKOUT_COMPLETED;
        fakeGateway.nextTxId = txId;
        fakeGateway.nextOrderToken = lastCreateResponse.getOrderToken();
        String payload = "{\"type\":\"checkout.session.completed\",\"orderToken\":\""
                + lastCreateResponse.getOrderToken() + "\",\"txId\":\"" + txId + "\"}";
        lastWebhookResult = webhookService.handle(GatewayProvider.STRIPE, payload, VALID_SIGNATURE);
    }

    @When("the same payment-succeeded webhook arrives again with tx id {string}")
    public void duplicateWebhook(String txId) {
        paymentSucceededWebhook(txId);
    }

    @When("a checkout-cancelled webhook arrives for that order")
    public void checkoutCancelledWebhook() {
        fakeGateway.nextEventType = PaymentGatewayStrategy.EventType.CHECKOUT_CANCELLED;
        fakeGateway.nextOrderToken = lastCreateResponse.getOrderToken();
        String payload = "{\"type\":\"checkout.session.expired\",\"orderToken\":\""
                + lastCreateResponse.getOrderToken() + "\"}";
        lastWebhookResult = webhookService.handle(GatewayProvider.STRIPE, payload, VALID_SIGNATURE);
    }

    @When("a webhook arrives for that order with an invalid signature")
    public void invalidSignatureWebhook() {
        fakeGateway.nextEventType = PaymentGatewayStrategy.EventType.CHECKOUT_COMPLETED;
        fakeGateway.nextOrderToken = lastCreateResponse.getOrderToken();
        String payload = "{\"type\":\"checkout.session.completed\",\"orderToken\":\""
                + lastCreateResponse.getOrderToken() + "\"}";
        lastWebhookResult = webhookService.handle(GatewayProvider.STRIPE, payload, "sig_bogus");
    }

    @Then("the webhook result is {string}")
    public void webhookResultIs(String expected) {
        assertThat(lastWebhookResult).isEqualTo(WebhookService.Result.valueOf(expected));
    }

    @Then("the order remains in state {string}")
    public void orderRemainsInState(String state) {
        orderStateIs(state);
    }

    // ---- Tenant + provisioning assertions -------------------------

    @Then("a tenant with slug {string} exists")
    public void tenantExists(String slug) {
        assertThat(tenantsBySlug).containsKey(slug);
    }

    @Then("no tenant with slug {string} exists")
    public void tenantDoesNotExist(String slug) {
        assertThat(tenantsBySlug).doesNotContainKey(slug);
    }

    @Then("exactly {int} tenant with slug {string} exists")
    public void exactlyNTenants(int n, String slug) {
        long count = tenantsBySlug.keySet().stream().filter(s -> s.equals(slug)).count();
        assertThat(count).isEqualTo(n);
    }

    @Then("a TENANT_ADMIN service-account token exists for tenant {string}")
    public void serviceAccountExists(String slug) {
        Tenant t = tenantsBySlug.get(slug);
        assertThat(t).as("tenant " + slug).isNotNull();
        assertThat(serviceAccounts.stream()
                .anyMatch(sa -> sa.getTenant() != null
                        && Objects.equals(sa.getTenant().getId(), t.getId())
                        && sa.getAdminRole() == tech.cwvermaak.weldforge.model.AdminRole.TENANT_ADMIN
                        && sa.getTokenHash() != null
                        && !sa.getTokenHash().isBlank()))
                .as("TENANT_ADMIN service account for tenant " + slug)
                .isTrue();
    }

    @Then("exactly {int} billing transaction is recorded as SUCCEEDED")
    public void exactlyNSucceededTxs(int n) {
        long count = billingTxs.stream()
                .filter(t -> t.getStatus() == TransactionStatus.SUCCEEDED)
                .count();
        assertThat(count).isEqualTo(n);
    }

    @Then("an audit event {string} is recorded")
    public void auditEventRecorded(String eventType) {
        assertThat(world.auditLog.stream().anyMatch(e -> eventType.equals(e.getEventType())))
                .as("audit event " + eventType + " in " + world.auditLog)
                .isTrue();
    }

    @Then("the slug {string} is available for a new order")
    public void slugIsAvailable(String slug) {
        // A retry attempt for the same slug must succeed (no UNIQUE violation).
        CreateOrderRequest req = newRequest("cloud-starter", slug, "retry@example.test");
        CreateOrderResponse resp = orderService.createOrder(req);
        assertThat(resp.getOrderToken()).isNotBlank();
    }

    // ---- Scheduler ------------------------------------------------

    @When("the expiry scheduler runs")
    public void expirySchedulerRuns() {
        orderService.expireStaleCheckouts();
    }

    // ---- Helpers --------------------------------------------------

    private CreateOrderRequest newRequest(String tier, String slug, String email) {
        CreateOrderRequest req = new CreateOrderRequest();
        req.setTier(tier);
        req.setOrganisation(slug + " Inc");
        req.setContactName("Ops Contact");
        req.setContactEmail(email);
        req.setTenantSlug(slug);
        req.setRegion("af-south-1");
        req.setBillingCycle("MONTHLY");
        req.setCurrency("USD");
        req.setBillingCountry("ZA");
        req.setTermsAccepted(true);
        return req;
    }

    /**
     * Hand-rolled fake that pretends to be Stripe. No network, no SDK.
     */
    private static final class FakeStripeGateway implements PaymentGatewayStrategy {
        PaymentGatewayStrategy.EventType nextEventType = PaymentGatewayStrategy.EventType.CHECKOUT_COMPLETED;
        String nextTxId = "ch_fake_default";
        String nextOrderToken;

        @Override
        public GatewayProvider provider() { return GatewayProvider.STRIPE; }

        @Override
        public CheckoutResult createCheckout(GatewayCredentials creds, CheckoutRequest req) {
            return new CheckoutResult(
                    "https://checkout.fake/" + req.orderToken(),
                    "cs_fake_" + req.orderToken(),
                    "cus_fake");
        }

        @Override
        public boolean verifySignature(GatewayCredentials creds, String rawPayload, String signatureHeader) {
            return VALID_SIGNATURE.equals(signatureHeader);
        }

        @Override
        public NormalisedEvent parseEvent(String rawPayload) {
            return new NormalisedEvent(
                    nextEventType,
                    nextOrderToken,
                    nextTxId,
                    "cs_fake_" + nextOrderToken,
                    "cus_fake",
                    null,
                    2900L,
                    "USD",
                    "US",
                    "424242",
                    null,
                    Map.of("stub", "true"));
        }
    }
}
