package tech.cwvermaak.intellisso.model.payment;

import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;

@Entity
@Table(name = "billing_transactions")
@Getter @Setter @NoArgsConstructor @AllArgsConstructor @Builder
public class BillingTransaction {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "subscription_id")
    private Subscription subscription;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "pending_order_id")
    private PendingOrder pendingOrder;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "gateway_id")
    private PaymentGateway gateway;

    @Column(name = "gateway_transaction_id", nullable = false, length = 255)
    private String gatewayTransactionId;

    @Column(name = "amount_cents", nullable = false)
    private long amountCents;

    @Column(nullable = false, length = 3)
    private String currency;

    @Column(name = "fee_cents")
    private Long feeCents;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 16)
    private TransactionStatus status;

    @Column(name = "failure_reason", length = 1024)
    private String failureReason;

    @Column(name = "card_country", length = 2)
    private String cardCountry;

    @Column(length = 8)
    private String bin;

    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @Column(name = "completed_at")
    private LocalDateTime completedAt;

    @PrePersist
    void onCreate() {
        if (createdAt == null) createdAt = LocalDateTime.now();
    }
}
