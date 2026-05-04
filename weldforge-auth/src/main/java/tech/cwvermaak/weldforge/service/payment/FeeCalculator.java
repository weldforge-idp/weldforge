package tech.cwvermaak.weldforge.service.payment;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import tech.cwvermaak.weldforge.model.payment.PaymentGateway;

import java.util.Map;

/**
 * Computes the effective fee in cents for a given (gateway, transaction)
 * pair. Pure function — no I/O other than BIN-country resolution which
 * the caller provides.
 *
 * <p>Fee structure JSONB shape (all keys optional; missing keys default
 * to 0):
 * <pre>{
 *   "percent":             2.9,
 *   "fixed_cents":         30,
 *   "intl_percent":        3.9,
 *   "intl_fixed_cents":    30,
 *   "conversion_percent":  0.5,
 *   "home_country":        "US"
 * }</pre>
 */
@Service
@RequiredArgsConstructor
public class FeeCalculator {

    /**
     * @param gateway         candidate gateway
     * @param amountCents     transaction amount
     * @param txCurrency      3-letter transaction currency
     * @param cardCountry     alpha-2 country of the payment instrument; may be null
     *                        if BIN lookup failed (treated as international)
     * @return fee in cents, rounded up to the nearest cent
     */
    public long computeFeeCents(PaymentGateway gateway,
                                 long amountCents,
                                 String txCurrency,
                                 String cardCountry) {
        Map<String, Object> fs = gateway.getFeeStructure();
        if (fs == null) fs = Map.of();

        String homeCountry = str(fs.get("home_country"));
        boolean isIntl = cardCountry == null || homeCountry == null
                      || !cardCountry.equalsIgnoreCase(homeCountry);

        double pct       = isIntl ? num(fs.get("intl_percent"),     num(fs.get("percent"),     0.0))
                                  :                                  num(fs.get("percent"),     0.0);
        long   fixed     = isIntl ? (long) num(fs.get("intl_fixed_cents"),
                                              num(fs.get("fixed_cents"), 0.0))
                                  : (long) num(fs.get("fixed_cents"), 0.0);
        double convPct   = needsConversion(gateway, txCurrency)
                           ? num(fs.get("conversion_percent"), 0.0) : 0.0;

        double feeMajor  = (amountCents * (pct + convPct) / 100.0) + fixed;
        return (long) Math.ceil(feeMajor);
    }

    private boolean needsConversion(PaymentGateway gateway, String txCurrency) {
        if (txCurrency == null || gateway.getSupportedCurrencies() == null) return false;
        return !gateway.getSupportedCurrencies().contains(txCurrency.toUpperCase());
    }

    private static double num(Object raw, double fallback) {
        if (raw instanceof Number n) return n.doubleValue();
        if (raw instanceof String s) {
            try { return Double.parseDouble(s); } catch (NumberFormatException ignored) {}
        }
        return fallback;
    }

    private static String str(Object raw) {
        return raw == null ? null : raw.toString();
    }
}
