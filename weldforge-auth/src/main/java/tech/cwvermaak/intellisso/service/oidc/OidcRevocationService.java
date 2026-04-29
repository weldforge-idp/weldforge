package tech.cwvermaak.intellisso.service.oidc;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import tech.cwvermaak.intellisso.model.OidcClient;
import tech.cwvermaak.intellisso.model.RevokedOidcToken;
import tech.cwvermaak.intellisso.model.Tenant;
import tech.cwvermaak.intellisso.model.TenantSigningKey;
import tech.cwvermaak.intellisso.repository.RevokedOidcTokenRepository;
import tech.cwvermaak.intellisso.service.audit.AuditEventTypes;
import tech.cwvermaak.intellisso.service.audit.AuditService;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Map;

/**
 * RFC 7009 token revocation. Inserts the token's hash into the
 * revocation list so subsequent introspection calls return inactive.
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
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();
        } catch (JwtException | IllegalStateException | IllegalArgumentException e) {
            log.debug("Revoke called for unrecognised token: {}", e.getMessage());
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

        auditService.log(tech.cwvermaak.intellisso.model.AuditEvent.builder()
                .eventType(AUDIT_TOKEN_REVOKED)
                .outcome(tech.cwvermaak.intellisso.model.AuditEvent.Outcome.SUCCESS)
                .tenant(tenant)
                .targetType(AuditEventTypes.TARGET_USER)
                .targetId(String.valueOf(claims.getSubject()))
                .metadata(Map.of(
                        "client_id", client.getClientId(),
                        "tenant", tenant.getSlug(),
                        "expires_at", expiresAt.toString())));
    }
}
