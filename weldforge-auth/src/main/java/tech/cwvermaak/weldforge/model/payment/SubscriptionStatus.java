package tech.cwvermaak.weldforge.model.payment;

public enum SubscriptionStatus {
    /** Paid, in the current billing period. */
    ACTIVE,
    /** Renewal failed; grace period before forced cancellation. */
    PAST_DUE,
    /** Cancelled by the customer or operator; will run to period end. */
    CANCELLED,
    /** Period ended after cancellation — fully inactive. */
    ENDED
}
