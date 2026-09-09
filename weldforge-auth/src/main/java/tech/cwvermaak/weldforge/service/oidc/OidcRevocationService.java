package tech.cwvermaak.weldforge.service.oidc;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import tech.cwvermaak.weldforge.model.OidcClient;
import tech.cwvermaak.weldforge.model.RevokedOidcToken;
import tech.cwvermaak.weldforge.model.Tenant;
import tech.cwvermaak.weldforge.model.TenantSigningKey;
import tech.cwvermaak.weldforge.model.RefreshToken;
import tech.cwvermaak.weldforge.repository.RefreshTokenRepository;
import tech.cwvermaak.weldforge.repository.RevokedOidcTokenRepository;
import tech.cwvermaak.weldforge.service.audit.AuditEventTypes;
import tech.cwvermaak.weldforge.service.audit.AuditService;
import tech.cwvermaak.weldforge.service.security.RefreshTokenFamilyRevoker;
import tech.cwvermaak.weldforge.service.security.RefreshTokenService;

import java.util.Optional;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Map;

/**
 * RFC 7009 token revocation.
 *
 * <p>Two token types reach this endpoint and they are stored completely
 * differently. An <b>access token</b> is a tenant-signed JWT held only by the
 * client, so revoking it means writing its hash to a blocklist introspection
 * consults. A <b>refresh token</b> is opaque and already has a database row, so
 * revoking it means killing its family.
 *
 * <p>Until CONF-6.3 only the first was handled. A refresh token failed to parse
 * as a tenant JWT, fell into the catch block, logged at debug and returned --
 * and because the spec mandates 200 either way, the caller got a success
 * response for a revocation that never happened. A relying party ending a
 * user's session was told it had, and hadn't. That is worse than an error:
 * an error would have been retried.
 *
 * Tenant-scoped: a token from tenant A presented by tenant B's client
 * is silently treated as success per the spec ("revocation always
 * returns 200 to avoid leaking whether a token existed") but the
 * actual blocklist row is only written for tokens that genuinely
 * belong to the calling tenant + client.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class OidcRevocationService {

    public static final String AUDIT_TOKEN_REVOKED = "oidc.token.revoked";

    private final TenantSigningKeyService signingKeyService;
    private final RevokedOidcTokenRepository revocationRepository;
    private final AuditService auditService;
    private final RefreshTokenRepository refreshTokenRepository;
    private final RefreshTokenFamilyRevoker familyRevoker;

    @Transactional
    public void revoke(String token, Tenant tenant, OidcClient client, String tenantIssuer) {
        if (token == null || token.isBlank()) return;

        // Parse the token, but swallow any failure — the spec mandates
        // a 200 response either way to avoid leaking token existence.
        Claims claims;
        try {
            claims = Jwts.parser()
                    .keyLocator(jws -> {
                        String kid = jws.get("kid").toString();
                        TenantSigningKey row = signingKeyService.requireByKid(kid);
                        if (!row.getTenant().getId().equals(tenant.getId())) {
                            throw new IllegalStateException("kid belongs to a different tenant");
                        }
                        return signingKeyService.loadPublicKey(row);
                    })
                    .clockSkewSeconds(60)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();
        } catch (JwtException | IllegalStateException | IllegalArgumentException e) {
            // Not a tenant-signed JWT. Before CONF-6.3 that ended here with a
            // 200 and nothing revoked. An opaque refresh token looks exactly
            // like this, so try that interpretation before giving up.
            // Debug is right here: this is the NORMAL path for an opaque
            // refresh token, not a fault. The interesting outcomes are logged
            // by revokeRefreshToken below.
            log.debug("Revoke: not a tenant JWT, trying refresh token: {}", e.getMessage());
            revokeRefreshToken(token, tenant, client);
            return;
        }

        // Issuer must match — protects against cross-tenant revocation.
        if (!tenantIssuer.equals(String.valueOf(claims.get("iss")))) return;

        // Client id must match the calling client unless the token has
        // no client_id at all (rare; defensive only).
        Object cidClaim = claims.get("client_id");
        if (cidClaim != null && !client.getClientId().equals(cidClaim.toString())) {
            log.warn("Revoke refused: token belongs to a different client_id");
            return;
        }

        String hash = OidcIntrospectionService.hash(token);
        if (revocationRepository.existsByTokenHash(hash)) {
            // Idempotent — second revoke is a no-op success.
            return;
        }

        LocalDateTime expiresAt = claims.getExpiration() == null
                ? LocalDateTime.now().plusDays(1)
                : LocalDateTime.ofInstant(
                        Instant.ofEpochMilli(claims.getExpiration().getTime()),
                        ZoneId.systemDefault());

        RevokedOidcToken row = RevokedOidcToken.builder()
                .tokenHash(hash)
                .tenant(tenant)
                .client(client)
                .expiresAt(expiresAt)
                .revokedReason("client_request")
                .build();
        revocationRepository.save(row);

        auditService.log(tech.cwvermaak.weldforge.model.AuditEvent.builder()
                .eventType(AUDIT_TOKEN_REVOKED)
                .outcome(tech.cwvermaak.weldforge.model.AuditEvent.Outcome.SUCCESS)
                .tenant(tenant)
                .targetType(AuditEventTypes.TARGET_USER)
                .targetId(String.valueOf(claims.getSubject()))
                .metadata(Map.of(
                        "client_id", client.getClientId(),
                        "tenant", tenant.getSlug(),
                        "expires_at", expiresAt.toString())));
    }

    /**
     * Revoke an opaque refresh token by killing its family (CONF-6.3).
     *
     * <p>Rotation already makes a family the unit of revocation: a token and
     * every successor minted from it share one {@code familyId}. Revoking only
     * the presented token would leave its successor alive, which is not what a
     * caller saying "revoke this" means.
     *
     * <p>Both bindings are re-checked before anything is written, for the same
     * reason {@code rotateForClient} checks them: without the client check, any
     * client holding a token hash could revoke another client's sessions, which
     * turns a cleanup endpoint into a denial-of-service primitive.
     *
     * <p>Silent on every failure. RFC 7009 §2.2 requires 200 for an unknown
     * token so the endpoint cannot be used to probe which tokens exist, and
     * that has to hold for a token belonging to someone else too — otherwise
     * the response time or an error would leak exactly what the 200 hides.
     */
    private void revokeRefreshToken(String token, Tenant tenant, OidcClient client) {
        Optional<RefreshToken> found =
                refreshTokenRepository.findByTokenHash(RefreshTokenService.hash(token));
        if (found.isEmpty()) {
            // RFC 7009 §2.2 requires a 200 for an unknown token, so the caller
            // learns nothing -- but WE should. A client that believes it
            // revoked a session and did not is a live incident, and the 200
            // guarantees nobody will report it.
            log.warn("Revocation matched no token: the caller was told it succeeded "
                    + "(client_id={} tenant={})", client.getClientId(), tenant.getSlug());
            return;
        }
        RefreshToken row = found.get();

        if (row.getTenant() == null || !row.getTenant().getId().equals(tenant.getId())) {
            log.warn("Revoke refused, cross-tenant: presented_by_tenant={} token_tenant={} client_id={}",
                    tenant.getSlug(),
                    row.getTenant() == null ? "(none)" : row.getTenant().getSlug(),
                    client.getClientId());
            return;
        }
        if (row.getClient() == null || !row.getClient().getId().equals(client.getId())) {
            // Someone holding a token hash they were not issued. Worth naming
            // both sides: this is either a broken integration or a probe.
            log.warn("Revoke refused, wrong client: presented_by={} issued_to={} tenant={}",
                    client.getClientId(),
                    row.getClient() == null ? "(none)" : row.getClient().getClientId(),
                    tenant.getSlug());
            return;
        }

        int revoked = familyRevoker.revoke(row.getFamilyId(), "client_request");

        auditService.log(tech.cwvermaak.weldforge.model.AuditEvent.builder()
                .eventType(AUDIT_TOKEN_REVOKED)
                .outcome(tech.cwvermaak.weldforge.model.AuditEvent.Outcome.SUCCESS)
                .tenant(tenant)
                .actorUser(row.getUser())
                .targetType("refresh_token_family")
                .targetId(row.getFamilyId().toString())
                .metadata(Map.of(
                        "client_id", client.getClientId(),
                        "tenant", tenant.getSlug(),
                        "token_type", "refresh_token",
                        "revoked_count", revoked)));
    }
}
