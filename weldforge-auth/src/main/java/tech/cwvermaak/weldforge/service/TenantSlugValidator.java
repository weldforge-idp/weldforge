package tech.cwvermaak.weldforge.service;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import tech.cwvermaak.weldforge.config.tenant.PublicHostProperties;
import tech.cwvermaak.weldforge.repository.TenantSlugHoldbackRepository;

import java.time.LocalDateTime;
import java.util.regex.Pattern;

/**
 * B-PROV-1: single source of truth for tenant-slug validation, so every path
 * that mints a tenant applies the SAME rules — the admin API
 * ({@code TenantService.createTenant}) <em>and</em> the self-service payment
 * funnel ({@code OrderService.createOrder} / {@code TenantProvisioningService}),
 * which previously persisted the raw requested slug with no checks.
 *
 * <p>Enforces: format, reserved labels (a slug shadowing {@code www}/{@code api}/
 * {@code admin}/… would be unreachable via its subdomain), and the post-delete
 * holdback window (anti-identity-confusion). See {@code docs/auth-url-spec.md}.
 */
@Component
@RequiredArgsConstructor
public class TenantSlugValidator {

    private static final Pattern SLUG_FORMAT =
            Pattern.compile("^[a-z0-9][a-z0-9-]{0,62}[a-z0-9]$");

    private final PublicHostProperties publicHost;
    private final TenantSlugHoldbackRepository slugHoldbackRepository;

    /**
     * Validate and normalise a requested slug.
     *
     * @return the trimmed, lower-cased slug
     * @throws IllegalArgumentException if the slug is null, malformed, reserved,
     *         or on holdback (mapped to HTTP 400 by GlobalExceptionHandler)
     */
    public String validate(String slug) {
        if (slug == null) throw new IllegalArgumentException("slug is required");
        String normalised = slug.trim().toLowerCase();
        if (!SLUG_FORMAT.matcher(normalised).matches()) {
            throw new IllegalArgumentException(
                "slug must be lowercase alphanumeric + dashes, 2-64 chars, not starting/ending with '-'");
        }
        if (publicHost.getReservedLabels() != null
                && publicHost.getReservedLabels().contains(normalised)) {
            throw new IllegalArgumentException(
                "slug '" + normalised + "' is reserved — pick a different one");
        }
        int holdbackDays = publicHost.getSlugHoldbackDays();
        if (holdbackDays > 0) {
            slugHoldbackRepository.findFirstBySlugOrderByReleasedAtDesc(normalised)
                    .ifPresent(h -> {
                        LocalDateTime expiresAt = h.getReleasedAt().plusDays(holdbackDays);
                        if (expiresAt.isAfter(LocalDateTime.now())) {
                            throw new IllegalArgumentException(
                                "slug '" + normalised + "' was recently released and "
                              + "is on holdback until " + expiresAt + " — pick a different one");
                        }
                    });
        }
        return normalised;
    }
}
