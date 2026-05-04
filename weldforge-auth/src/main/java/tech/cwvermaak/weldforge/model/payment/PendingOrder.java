package tech.cwvermaak.weldforge.model.payment;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;
import tech.cwvermaak.weldforge.model.Tenant;

import java.time.LocalDateTime;
import java.util.Map;

@Entity
@Table(name = "pending_orders")
@Getter @Setter @NoArgsConstructor @AllArgsConstructor @Builder
public class PendingOrder {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "order_token", nullable = false, unique = true, length = 64)
    private String orderToken;

    @Column(nullable = false, length = 32)
    private String tier;

    @Column(nullable = false, length = 255)
    private String organisation;

    @Column(name = "contact_name", nullable = false, length = 255)
    private String contactName;

    @Column(name = "contact_email", nullable = false, length = 320)
    private String contactEmail;

    @Column(name = "requested_tenant_slug", length = 64)
    private String requestedTenantSlug;

    @Column(length = 32)
    private String region;

    @Column(name = "billing_cycle", nullable = false, length = 16)
    private String billingCycle;

    @Column(nullable = false, length = 3)
    private String currency;

    @Column(name = "amount_cents", nullable = false)
    private long amountCents;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "selected_gateway_id")
    private PaymentGateway selectedGateway;

    @Column(name = "gateway_session_id", length = 255)
    private String gatewaySessionId;

    @Column(name = "gateway_customer_id", length = 255)
    private String gatewayCustomerId;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 32)
    @Builder.Default
    private OrderStatus status = OrderStatus.CREATED;

    @Column(name = "provisioning_attempts", nullable = false)
    @Builder.Default
    private int provisioningAttempts = 0;

    @Column(name = "last_provisioning_error", length = 1024)
    private String lastProvisioningError;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "provisioned_tenant_id")
    private Tenant provisionedTenant;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(columnDefinition = "jsonb")
    @Builder.Default
    private Map<String, Object> metadata = Map.of();

    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @Column(name = "slug_reservation_expires", nullable = false)
    private LocalDateTime slugReservationExpires;

    @Column(name = "paid_at")
    private LocalDateTime paidAt;

    @Column(name = "provisioned_at")
    private LocalDateTime provisionedAt;

    @PrePersist
    void onCreate() {
        if (createdAt == null) createdAt = LocalDateTime.now();
    }
}
