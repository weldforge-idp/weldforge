package tech.cwvermaak.intellisso.service.payment;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import tech.cwvermaak.intellisso.model.payment.GatewayScope;
import tech.cwvermaak.intellisso.model.payment.PaymentGateway;
import tech.cwvermaak.intellisso.repository.PaymentGatewayRepository;

import java.util.Comparator;
import java.util.List;

/**
 * Picks the cheapest gateway for a transaction. Inputs:
 * <ul>
 *   <li>scope (PLATFORM for WeldForge billing its subscribers; TENANT for
 *       a tenant billing its end-users)</li>
 *   <li>currency + billing country + card country</li>
 * </ul>
 *
 * Filters out gateways that do not support the currency or country, then
 * sorts ascending by {@link FeeCalculator#computeFeeCents} with {@code
 * priority desc, id asc} as the deterministic tie-break.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class PaymentRoutingService {

    private final PaymentGatewayRepository gatewayRepository;
    private final FeeCalculator feeCalculator;

    public record Quote(PaymentGateway gateway, long feeCents) {}

    /**
     * Operator-scope routing (WeldForge billing a subscriber).
     */
    public List<Quote> rankPlatform(long amountCents,
                                     String currency,
                                     String billingCountry,
                                     String cardCountry) {
        return rank(gatewayRepository.findEnabledPlatformGateways(),
                amountCents, currency, billingCountry, cardCountry);
    }

    /**
     * Tenant-scope routing (tenant billing its own end-user).
     */
    public List<Quote> rankForTenant(Long tenantId,
                                      long amountCents,
                                      String currency,
                                      String billingCountry,
                                      String cardCountry) {
        return rank(gatewayRepository.findEnabledTenantGateways(tenantId),
                amountCents, currency, billingCountry, cardCountry);
    }

    private List<Quote> rank(List<PaymentGateway> candidates,
                              long amountCents,
                              String currency,
                              String billingCountry,
                              String cardCountry) {
        String curr = currency == null ? null : currency.toUpperCase();
        String ctry = billingCountry == null ? null : billingCountry.toUpperCase();

        return candidates.stream()
                .filter(g -> supportsCurrency(g, curr))
                .filter(g -> supportsCountry(g, ctry))
                .map(g -> new Quote(g, feeCalculator.computeFeeCents(g, amountCents, curr, cardCountry)))
                .sorted(Comparator
                        .comparingLong(Quote::feeCents)
                        .thenComparing((a, b) -> Integer.compare(b.gateway().getPriority(), a.gateway().getPriority()))
                        .thenComparingLong(q -> q.gateway().getId()))
                .toList();
    }

    private static boolean supportsCurrency(PaymentGateway g, String currency) {
        if (currency == null) return true;
        return g.getSupportedCurrencies() != null
                && g.getSupportedCurrencies().stream().anyMatch(c -> c.equalsIgnoreCase(currency));
    }

    private static boolean supportsCountry(PaymentGateway g, String country) {
        if (country == null) return true;
        if (g.getSupportedCountries() == null || g.getSupportedCountries().isEmpty()) return true;
        return g.getSupportedCountries().stream().anyMatch(c -> c.equalsIgnoreCase(country));
    }
}
