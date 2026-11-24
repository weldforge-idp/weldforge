package tech.cwvermaak.weldforge.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import tech.cwvermaak.weldforge.model.Tenant;
import tech.cwvermaak.weldforge.repository.TenantRepository;
import tech.cwvermaak.weldforge.service.audit.AuditEventTypes;
import tech.cwvermaak.weldforge.service.audit.AuditService;

import java.util.Arrays;
import java.util.List;
import java.util.Locale;

/**
 * Identity-proofing V2c — watchword auto-flagging.
 *
 * <p>A newly-created tenant whose slug contains a brand-sensitive substring
 * ({@code bank}, {@code pay}, {@code secure}, {@code official}, …) is flagged
 * into the same SUPER_ADMIN review queue the V2b domain gate uses, rather than
 * being trusted on sight. It deliberately does <b>not</b> block creation — a
 * legitimate {@code firstpay} may be real — but a human should look before the
 * tenant is treated as verified. The matching word is recorded as the review
 * reason and audited.
 *
 * <p>The watchword list is configurable via {@code app.identity.slug-watchwords}
 * so an operator can tune it without a deploy of this class.
 */
@Component
@Slf4j
public class SlugWatchwordPolicy {

    private final List<String> watchwords;
    private final TenantRepository tenantRepository;
    private final AuditService auditService;

    public SlugWatchwordPolicy(
            @Value("${app.identity.slug-watchwords:"
                   + "bank,pay,secure,official,verify,login,account,wallet,"
                   + "paypal,visa,mastercard,invoice,billing,support,admin}") String configured,
            TenantRepository tenantRepository,
            AuditService auditService) {
        this.watchwords = Arrays.stream(configured.split(","))
                .map(s -> s.trim().toLowerCase(Locale.ROOT))
                .filter(s -> !s.isBlank())
                .toList();
        this.tenantRepository = tenantRepository;
        this.auditService = auditService;
    }

    /** The first configured watchword the slug contains, or null if none. */
    public String matched(String slug) {
        if (slug == null) return null;
        String s = slug.toLowerCase(Locale.ROOT);
        for (String w : watchwords) {
            if (s.contains(w)) return w;
        }
        return null;
    }

    /**
     * If the (already-persisted) tenant's slug contains a watchword, flag it for
     * super-admin review, persist the flag, and audit. Call after the tenant has
     * an id. Returns the matched watchword, or null when the slug is clean.
     */
    public String flagIfWatchword(Tenant tenant) {
        if (tenant == null) return null;
        String word = matched(tenant.getSlug());
        if (word == null) return null;
        tenant.setVerificationReviewRequired(true);
        tenant.setVerificationReviewReason(
                "slug contains brand-sensitive watchword '" + word + "' (V2c auto-flag)");
        tenantRepository.save(tenant);
        auditService.recordAdmin(AuditEventTypes.TENANT_SLUG_WATCHWORD_FLAGGED, null,
                AuditEventTypes.TARGET_TENANT, String.valueOf(tenant.getId()),
                AuditService.meta("slug", tenant.getSlug(), "watchword", word));
        log.info("V2c: tenant slug '{}' flagged for review (watchword '{}')", tenant.getSlug(), word);
        return word;
    }
}
