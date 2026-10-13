package tech.cwvermaak.weldforge.service.oidc;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import tech.cwvermaak.weldforge.model.OidcClient;
import tech.cwvermaak.weldforge.model.Tenant;

/**
 * How long an access token lives, resolved most-specific-first: this client,
 * then the tenant (PRD SSO-03), then the application default.
 *
 * <p>One component rather than the rule written out in each service, because
 * two of them need it and they have to agree. The issuing path decides what to
 * stamp on a token; the registration path decides whether a requested value is
 * allowed at all. If registration accepted a number that issuance then quietly
 * shortened, the admin who typed it would have no way to find out which one is
 * real -- {@code expires_in} would disagree with the client record and neither
 * would be wrong.
 *
 * <h2>A client may shorten its access tokens, never lengthen them</h2>
 *
 * <p>The tenant's effective TTL is a ceiling, enforced twice and for different
 * reasons:
 *
 * <ul>
 *   <li><b>At registration</b>, so an admin who asks for longer than the
 *       tenant allows sees a 400 against the field they typed, rather than a
 *       silent downgrade they discover later from a token.</li>
 *   <li><b>At issuance</b>, because a tenant may lower its own TTL after a
 *       client was registered. The stored value would then exceed a policy it
 *       was inside when it was written, and nothing would have re-validated
 *       it. Capping at the point of use means the tenant's number always
 *       wins, whenever it changed.</li>
 * </ul>
 *
 * <p>The ceiling exists because of dynamic client registration, not because of
 * admins: a tenant admin who wants longer-lived tokens can raise the tenant's
 * own TTL, which is the setting that is supposed to express that.
 * {@link OidcClientService#createForDynamicRegistration} runs the same
 * validation with <em>no admin session</em>, so without a ceiling a
 * self-registering client could grant itself a thirty-day access token. With
 * one, the worst it can do is give itself a shorter life than the tenant
 * allows, which is not an attack.
 *
 * <p>This deliberately differs from {@code refresh_token_ttl_s} beside it,
 * which takes a client value with no ceiling at all. That is a gap rather than
 * a model to copy: a refresh token is the longer-lived credential of the two,
 * so it is the one where an unbounded client override matters more. Closing it
 * is a breaking change for any client already relying on it and is tracked
 * separately.
 */
@Component
public class AccessTokenLifetime {

    /**
     * Deployment-wide default, in seconds. Configurable via
     * {@code app.oidc.access-token-seconds}.
     */
    @Value("${app.oidc.access-token-seconds:3600}")
    private long instanceDefaultSeconds = 3600L;

    /** Field injection, for Spring. */
    public AccessTokenLifetime() {
    }

    /** For tests and for any caller that already knows the default. */
    public AccessTokenLifetime(long instanceDefaultSeconds) {
        this.instanceDefaultSeconds = instanceDefaultSeconds;
    }

    /**
     * The tenant's effective access-token lifetime, and therefore the ceiling
     * for every client registered in it.
     *
     * @param tenant may be null, in which case the application default applies
     */
    public long forTenant(Tenant tenant) {
        if (tenant != null && tenant.getAccessTtlMs() != null && tenant.getAccessTtlMs() > 0) {
            return tenant.getAccessTtlMs() / 1000;
        }
        return instanceDefaultSeconds;
    }

    /**
     * The lifetime to stamp on a token issued to this client: the client's own
     * value when it asked for a shorter one, the tenant's otherwise.
     *
     * @param client may be null -- the client_credentials and refresh paths
     *               both always have one, but a null is treated as "no
     *               preference" rather than an error, so a caller that has no
     *               client in scope still gets the tenant's answer
     */
    public long forClient(Tenant tenant, OidcClient client) {
        long ceiling = forTenant(tenant);
        Integer requested = client == null ? null : client.getAccessTokenTtlSeconds();
        if (requested == null || requested <= 0) {
            return ceiling;
        }
        return Math.min(requested, ceiling);
    }
}
