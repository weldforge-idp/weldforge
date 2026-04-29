package tech.cwvermaak.intellisso.model.payment;

import java.util.EnumSet;
import java.util.Set;

/**
 * State machine for {@code pending_orders}. Enforced by the DB
 * check constraint of the same name. Transitions are owned by
 * {@code OrderService}.
 *
 * <pre>
 *   CREATED ──▶ CHECKOUT_STARTED ──▶ PAID ──▶ PROVISIONED (terminal)
 *       │              │              │
 *       │              │              ├─▶ PROVISIONING_FAILED ──▶ REFUNDED (terminal)
 *       │              │              │           ▲                   ▲
 *       │              │              └───────────┘ (24h retry budget)│
 *       │              │                                              │
 *       │              ├──▶ CANCELLED (terminal)                      │
 *       │              └──▶ EXPIRED   (terminal, slug TTL exhausted)  │
 *       └──▶ EXPIRED   (terminal) ─────────────────────────────────────┘
 * </pre>
 */
public enum OrderStatus {
    CREATED,
    CHECKOUT_STARTED,
    PAID,
    PROVISIONED,
    PROVISIONING_FAILED,
    CANCELLED,
    EXPIRED,
    REFUNDED;

    /** Active states — slug reservation still holds in these. */
    public static final Set<OrderStatus> ACTIVE = EnumSet.of(
            CREATED, CHECKOUT_STARTED, PAID, PROVISIONING_FAILED);

    /** Terminal states — no further transitions allowed. */
    public static final Set<OrderStatus> TERMINAL = EnumSet.of(
            PROVISIONED, CANCELLED, EXPIRED, REFUNDED);

    public boolean isActive()   { return ACTIVE.contains(this);   }
    public boolean isTerminal() { return TERMINAL.contains(this); }
}
