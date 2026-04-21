package tech.cwvermaak.intellisso.service.payment;

import java.util.Map;

/**
 * Hardcoded tier → amount lookup. Keeps the public marketing copy and
 * the backend billing consistent — see {@code weldforge.org/pricing}.
 *
 * <p>Deliberately not loaded from {@code application.yml}: these are
 * pricing commitments, not runtime configuration. Changing them is a
 * code review + marketing-site update in lock-step.
 */
public final class TierPricing {

    private TierPricing() {}

    // Monthly amounts in USD cents. Annual = monthly × 12 × 0.80 (20% annual discount).
    private static final Map<String, Long> MONTHLY_USD_CENTS = Map.of(
            "self-host-supported", 24_900L,
            "cloud-starter",           2_900L,
            "cloud-team",             14_900L,
            "cloud-business",         69_900L,
            "cloud-scale",           249_900L,
            "cloud-dedicated",       499_900L,
            "regulated",             999_900L
    );

    public static long amountCents(String tier, String billingCycle, String currency) {
        String key = tier == null ? "" : tier.toLowerCase();
        Long monthly = MONTHLY_USD_CENTS.get(key);
        if (monthly == null) {
            throw new IllegalArgumentException("Unknown tier: " + tier);
        }
        boolean annual = "ANNUAL".equalsIgnoreCase(billingCycle);

        long usdCents = annual
                ? Math.round(monthly * 12L * 0.80)
                : Math.round(monthly * 1.20);  // monthly = +20% surcharge

        // Currency conversion is best handled by the gateway itself
        // (Stripe, Paddle both support multi-currency price lookups).
        // For v1 we bill everything in USD unless the gateway converts.
        return usdCents;
    }

    public static boolean isKnownTier(String tier) {
        return tier != null && MONTHLY_USD_CENTS.containsKey(tier.toLowerCase());
    }
}
