package tech.cwvermaak.weldforge.service.payment;

import jakarta.persistence.EntityNotFoundException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import tech.cwvermaak.weldforge.model.AdminRole;
import tech.cwvermaak.weldforge.model.ServiceAccount;
import tech.cwvermaak.weldforge.model.Tenant;
import tech.cwvermaak.weldforge.model.payment.OrderStatus;
import tech.cwvermaak.weldforge.model.payment.PendingOrder;
import tech.cwvermaak.weldforge.model.payment.Subscription;
import tech.cwvermaak.weldforge.model.payment.SubscriptionStatus;
import tech.cwvermaak.weldforge.repository.PendingOrderRepository;
import tech.cwvermaak.weldforge.repository.ServiceAccountRepository;
import tech.cwvermaak.weldforge.repository.SubscriptionRepository;
import tech.cwvermaak.weldforge.repository.TenantRepository;
import tech.cwvermaak.weldforge.model.AuditEvent;
import tech.cwvermaak.weldforge.service.audit.AuditEventTypes;
import tech.cwvermaak.weldforge.service.audit.AuditService;
import tech.cwvermaak.weldforge.service.security.ApiKeyHasher;

import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.HexFormat;

/**
 * Runs the provisioning script after payment clears. Called only by the
 * webhook handler (on {@code markPaid} success) and the retry scheduler.
 *
 * <p>Operations:
 * <ol>
 *   <li>Create {@code tenants} row with the slug the customer reserved.</li>
 *   <li>Mint a one-shot {@code TENANT_ADMIN} service-account token and
 *       persist its SHA-256 hash.</li>
 *   <li>Create a {@code subscriptions} row bound to the tenant + gateway.</li>
 *   <li>Audit {@code tenant.provisioned}.</li>
 *   <li>Send the welcome email (currently logs to stdout — see the
 *       survey note on email templating).</li>
 * </ol>
 *
 * <p>Any failure throws {@link ProvisioningException} which the caller
 * translates to {@link OrderStatus#PROVISIONING_FAILED}. The scheduler
 * retries for 24 hours before transitioning to {@link OrderStatus#REFUNDED}.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class TenantProvisioningService {

    private final TenantRepository tenantRepository;
    private final ServiceAccountRepository serviceAccountRepository;
    private final SubscriptionRepository subscriptionRepository;
    private final PendingOrderRepository pendingOrderRepository;
    private final OrderService orderService;
    private final AuditService auditService;

    private static final SecureRandom RNG = new SecureRandom();

    @Transactional
    public ProvisioningResult provision(Long orderId) {
        PendingOrder order = pendingOrderRepository.findById(orderId)
                .orElseThrow(() -> new EntityNotFoundException("Unknown order: " + orderId));

        if (order.getStatus() != OrderStatus.PAID
                && order.getStatus() != OrderStatus.PROVISIONING_FAILED) {
            throw new ProvisioningException("Cannot provision from status " + order.getStatus());
        }
        if (order.getProvisionedTenant() != null) {
            // Re-entry safety: earlier attempt succeeded partway.
            return new ProvisioningResult(order.getProvisionedTenant(), null);
        }

        try {
            Tenant tenant = createTenant(order);
            String plaintextToken = mintServiceAccount(tenant);
            Subscription subscription = createSubscription(tenant, order);

            order.setProvisionedTenant(tenant);
            pendingOrderRepository.save(order);
            orderService.markProvisioned(orderId, tenant.getId());

            auditService.log(AuditEvent.builder()
                    .eventType(AuditEventTypes.TENANT_PROVISIONED_VIA_BILLING)
                    .actorEmail("system:billing")
                    .tenant(tenant)
                    .targetType(AuditEventTypes.TARGET_TENANT)
                    .targetId(String.valueOf(tenant.getId()))
                    .outcome(AuditEvent.Outcome.SUCCESS)
                    .metadata(AuditService.meta(
                            "order_token",    order.getOrderToken(),
                            "tier",           order.getTier(),
                            "billing_cycle",  order.getBillingCycle(),
                            "subscription",   String.valueOf(subscription.getId()),
                            "gateway",        order.getSelectedGateway().getProvider().name())));

            sendWelcome(order, tenant, plaintextToken);
            return new ProvisioningResult(tenant, plaintextToken);

        } catch (Exception ex) {
            log.error("Provisioning failed for order {}: {}", order.getOrderToken(), ex.getMessage(), ex);
            orderService.markProvisioningFailed(orderId, ex.getMessage());
            throw new ProvisioningException(ex.getMessage(), ex);
        }
    }

    // ---- Subroutines -----------------------------------------------

    private Tenant createTenant(PendingOrder order) {
        if (tenantRepository.existsBySlug(order.getRequestedTenantSlug())) {
            throw new ProvisioningException(
                    "Slug '" + order.getRequestedTenantSlug() + "' was taken between payment and provisioning.");
        }
        Tenant tenant = new Tenant();
        tenant.setSlug(order.getRequestedTenantSlug());
        tenant.setName(order.getOrganisation());
        tenant.setDisplayName(order.getOrganisation());
        tenant.setEnabled(true);
        return tenantRepository.save(tenant);
    }

    private String mintServiceAccount(Tenant tenant) {
        String plaintext = newServiceAccountToken();
        ServiceAccount sa = ServiceAccount.builder()
                .tenant(tenant)
                .name("bootstrap-admin")
                .description("Auto-issued at subscription provisioning. Rotate after first login.")
                .adminRole(AdminRole.TENANT_ADMIN)
                .tokenHash(ApiKeyHasher.hash(plaintext))
                .tokenPrefix(ApiKeyHasher.displayPrefix(plaintext))
                .enabled(true)
                .build();
        serviceAccountRepository.save(sa);
        return plaintext;
    }

    private Subscription createSubscription(Tenant tenant, PendingOrder order) {
        LocalDateTime now = LocalDateTime.now();
        LocalDateTime end = "ANNUAL".equalsIgnoreCase(order.getBillingCycle())
                ? now.plusYears(1)
                : now.plusMonths(1);
        Subscription sub = Subscription.builder()
                .tenant(tenant)
                .tier(order.getTier())
                .status(SubscriptionStatus.ACTIVE)
                .billingCycle(order.getBillingCycle())
                .currency(order.getCurrency())
                .amountCents(order.getAmountCents())
                .gateway(order.getSelectedGateway())
                .gatewayCustomerId(order.getGatewayCustomerId())
                .currentPeriodStart(now)
                .currentPeriodEnd(end)
                .build();
        return subscriptionRepository.save(sub);
    }

    private void sendWelcome(PendingOrder order, Tenant tenant, String plaintextToken) {
        // Email templating is not yet wired (see survey finding #6).
        // Emit a structured log line so ops can tail it or pipe to SES.
        log.info("WELCOME_EMAIL tenant={} slug={} contact={} token_prefix={} admin_portal=https://admin.weldforge.org/t/{}",
                tenant.getId(),
                tenant.getSlug(),
                order.getContactEmail(),
                ApiKeyHasher.displayPrefix(plaintextToken),
                tenant.getSlug());
    }

    private static String newServiceAccountToken() {
        byte[] buf = new byte[24];
        RNG.nextBytes(buf);
        return ApiKeyHasher.SERVICE_ACCOUNT_PREFIX + HexFormat.of().formatHex(buf);
    }

    public record ProvisioningResult(Tenant tenant, String plaintextToken) {}

    public static class ProvisioningException extends RuntimeException {
        public ProvisioningException(String message) { super(message); }
        public ProvisioningException(String message, Throwable cause) { super(message, cause); }
    }
}
