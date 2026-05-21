package tech.cwvermaak.weldforge.config.tenant;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Public-facing host config that drives both tenant resolution from the
 * Host header and outbound URL construction (password-reset emails, OIDC
 * unauthenticated-redirect to the tenant login). See
 * {@code docs/auth-url-spec.md}.
 *
 * <p>A request to {@code https://acme.sso.weldforge.org/login} resolves
 * to tenant {@code acme} when {@link #getBaseDomain()} is
 * {@code sso.weldforge.org} and {@code acme} is not a reserved label.</p>
 */
@ConfigurationProperties(prefix = "wf.public")
public class PublicHostProperties {

    /** Slug-shaped subdomain labels — first label of the Host header. */
    private static final Pattern SLUG = Pattern.compile("^[a-z0-9][a-z0-9-]{0,62}[a-z0-9]$");

    /** Base domain (no scheme, no leading dot) under which tenants are subdomained. */
    private String baseDomain = "sso.weldforge.org";

    /** Scheme used when building absolute outbound URLs. */
    private String scheme = "https";

    /**
     * Days a deleted tenant's slug stays on holdback before it can be
     * reused by a new tenant. Defends against identity-confusion
     * attacks where a stolen pre-deletion session lines up with a
     * freshly-issued post-recreation token on the same subdomain.
     * Set to 0 to disable the holdback (testing only — not safe in prod).
     */
    private int slugHoldbackDays = 90;

    /**
     * Subdomain labels that may never be used as a tenant slug. Two reasons:
     *
     * <ol>
     *   <li><b>Routing safety</b> — these labels are (or could be) used for
     *       infra hostnames, so allowing a tenant to claim them would create
     *       a phishing vector or routing collision.</li>
     *   <li><b>Brand confusion</b> — labels like {@code oauth}, {@code saml},
     *       {@code login}, {@code accounts} look authoritative; a tenant
     *       slug shaped like one of them on a wildcard cert would trick
     *       users into trusting a credential prompt from a tenant they
     *       don't know.</li>
     * </ol>
     *
     * <p>Enforced at <b>both</b> resolution time
     * ({@link #slugFromHost(String)}) and slug-creation time
     * ({@code TenantService.requireSlug}) — otherwise a tenant could exist
     * with one of these slugs but be permanently unreachable via its
     * subdomain.</p>
     */
    private List<String> reservedLabels = List.of(
            // Infrastructure / well-known
            "www", "api", "admin", "app", "mail", "static", "cdn", "assets",
            "health", "actuator", "metrics", "prometheus", "grafana",
            "swagger", "api-docs",
            // Environment markers
            "dev", "staging", "stage", "test", "prod", "production",
            // Identity / federation labels (phishing-prone)
            "auth", "oauth", "oauth2", "oidc", "saml", "scim", "sso",
            "account", "accounts", "login", "logout", "signin", "signup",
            "register", "verify", "reset", "password", "mfa", "totp",
            // Marketing / catch-all
            "blog", "docs", "support", "help", "status", "billing");

    public String getBaseDomain() { return baseDomain; }
    public void setBaseDomain(String baseDomain) {
        this.baseDomain = baseDomain == null ? null : baseDomain.trim().toLowerCase(Locale.ROOT);
    }

    public String getScheme() { return scheme; }
    public void setScheme(String scheme) {
        this.scheme = scheme == null ? "https" : scheme.trim().toLowerCase(Locale.ROOT);
    }

    public int getSlugHoldbackDays() { return slugHoldbackDays; }
    public void setSlugHoldbackDays(int slugHoldbackDays) {
        this.slugHoldbackDays = Math.max(slugHoldbackDays, 0);
    }

    public List<String> getReservedLabels() { return reservedLabels; }
    public void setReservedLabels(List<String> reservedLabels) {
        this.reservedLabels = reservedLabels == null ? List.of() : reservedLabels.stream()
                .map(s -> s == null ? "" : s.trim().toLowerCase(Locale.ROOT))
                .filter(s -> !s.isEmpty())
                .toList();
    }

    /**
     * Extract a tenant slug from a Host header value (which may carry a port).
     * Returns the first label when the host is {@code <label>.<baseDomain>},
     * the label looks like a slug, and it is not on the reserved list.
     * Returns {@code null} for the apex domain, for malformed hosts, or for
     * hosts that don't share the configured base domain.
     */
    public String slugFromHost(String hostHeader) {
        if (hostHeader == null || baseDomain == null || baseDomain.isBlank()) return null;
        String host = hostHeader.trim().toLowerCase(Locale.ROOT);
        int colon = host.indexOf(':');
        if (colon >= 0) host = host.substring(0, colon);
        if (host.isEmpty()) return null;
        if (host.equals(baseDomain)) return null;

        String suffix = "." + baseDomain;
        if (!host.endsWith(suffix)) return null;

        String label = host.substring(0, host.length() - suffix.length());
        // Only single-label subdomains resolve to a tenant. Multi-label
        // subdomains (e.g. "deploys.acme.sso.weldforge.org") fall through.
        if (label.isEmpty() || label.contains(".")) return null;
        if (!SLUG.matcher(label).matches()) return null;
        Set<String> reserved = Set.copyOf(reservedLabels);
        if (reserved.contains(label)) return null;
        return label;
    }

    /**
     * Build the public origin (scheme + host) for a tenant. Used to assemble
     * absolute redirect URLs (OIDC unauthenticated bounce) and email links.
     */
    public String originForTenant(String slug) {
        if (slug == null || slug.isBlank()) {
            return scheme + "://" + baseDomain;
        }
        return scheme + "://" + slug.trim().toLowerCase(Locale.ROOT) + "." + baseDomain;
    }

    /**
     * Domain attribute for session cookies. We deliberately set it to the
     * parent base-domain (a leading dot is implicit per RFC 6265) so the
     * cookie established on {@code acme.sso.weldforge.org/login} is also
     * sent to {@code sso.weldforge.org/t/acme/oauth2/authorize} — that is
     * where the OIDC consent step lands after a successful sign-in.
     *
     * <p>Side-effect: the cookie is also sent to every other tenant
     * subdomain. {@code JwtAuthenticationFilter} re-checks the JWT's
     * {@code tenant_id} against the resolved tenant on each request, so
     * the cookie is useless on a wrong tenant. The shared parent-domain
     * scope is the trade-off that keeps the apex OIDC flow working
     * without breaking password-manager distinctness (which is host-based
     * and independent of cookie scope).</p>
     *
     * <p>Returns {@code null} in dev / single-host setups (when the base
     * domain looks like a single label, e.g. {@code localhost}), so the
     * cookie stays host-only.</p>
     */
    public String cookieDomain() {
        if (baseDomain == null || baseDomain.isBlank()) return null;
        // Don't scope to a single-label parent (e.g. "localhost") — browsers
        // refuse those for security reasons, and host-only cookies work fine
        // when frontend + backend share one origin.
        if (!baseDomain.contains(".")) return null;
        return baseDomain;
    }
}
