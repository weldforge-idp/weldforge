package tech.cwvermaak.intellisso.service.oidc;

import io.jsonwebtoken.Jwts;
import io.micrometer.core.instrument.MeterRegistry;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import tech.cwvermaak.intellisso.model.OidcClient;
import tech.cwvermaak.intellisso.model.Tenant;
import tech.cwvermaak.intellisso.model.TenantSigningKey;
import tech.cwvermaak.intellisso.model.User;

import java.security.interfaces.RSAPrivateKey;
import java.time.Instant;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Mints RS256-signed access tokens and ID tokens using the tenant's
 * private key. The {@code kid} from {@link TenantSigningKey} is set in the
 * JWS header so verifiers can pick the matching key from the tenant's
 * JWKS endpoint.
 *
 * Multi-tenancy is enforced by construction: the only way to get a key
 * for tenant A is to ask {@link TenantSigningKeyService} for it, and the
 * issued token's {@code iss} claim contains the tenant's discovery URL,
 * so a token issued for one tenant cannot be replayed against another.
 */
@Service
@RequiredArgsConstructor
public class OidcTokenService {

    /** Access token lifetime in seconds. Configurable via {@code app.oidc.access-token-seconds}. */
    @Value("${app.oidc.access-token-seconds:3600}")
    private long accessTokenSeconds;

    /** ID token lifetime in seconds. */
    @Value("${app.oidc.id-token-seconds:3600}")
    private long idTokenSeconds;

    private final TenantSigningKeyService signingKeyService;
    private final MeterRegistry meterRegistry;

    /**
     * Issue an access token + ID token pair for a successful authorization
     * code exchange. The {@code nonce} from the original /authorize request
     * is mirrored into the ID token per the OIDC spec.
     */
    public IssuedTokens issueForCodeExchange(Tenant tenant, OidcClient client, User user,
                                             List<String> scopes, String nonce, String issuer) {
        TenantSigningKey key = signingKeyService.getOrCreateActive(tenant);
        RSAPrivateKey privateKey = signingKeyService.loadPrivateKey(key);
        Instant now = Instant.now();

        String accessToken = buildAccessToken(client, user, scopes, issuer, key.getKid(), privateKey, now);
        String idToken     = buildIdToken(client, user, nonce, issuer, key.getKid(), privateKey, now);

        meterRegistry.counter("sso.token.issued", "grant_type", "authorization_code",
                "tenant", tenant.getSlug()).increment();
        return new IssuedTokens(accessToken, idToken, accessTokenSeconds);
    }

    public String issueForClientCredentials(Tenant tenant, OidcClient client, List<String> scopes, String issuer) {
        TenantSigningKey key = signingKeyService.getOrCreateActive(tenant);
        RSAPrivateKey privateKey = signingKeyService.loadPrivateKey(key);
        Instant now = Instant.now();
        meterRegistry.counter("sso.token.issued", "grant_type", "client_credentials",
                "tenant", tenant.getSlug()).increment();
        return buildAccessToken(client, null, scopes, issuer, key.getKid(), privateKey, now);
    }

    private String buildAccessToken(OidcClient client, User user, List<String> scopes,
                                    String issuer, String kid, RSAPrivateKey privateKey, Instant now) {
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("iss", issuer);
        claims.put("aud", client.getClientId());
        claims.put("client_id", client.getClientId());
        claims.put("scope", String.join(" ", scopes));
        claims.put("token_type", "access");
        if (user != null) {
            claims.put("sub", String.valueOf(user.getId()));
            claims.put("email", user.getEmail());
            if (user.getName() != null) claims.put("name", user.getName());
        } else {
            // Client credentials grant — there's no end-user.
            claims.put("sub", client.getClientId());
        }
        return Jwts.builder()
                .header().keyId(kid).and()
                .claims(claims)
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plusSeconds(accessTokenSeconds)))
                .signWith(privateKey, Jwts.SIG.RS256)
                .compact();
    }

    private String buildIdToken(OidcClient client, User user, String nonce,
                                String issuer, String kid, RSAPrivateKey privateKey, Instant now) {
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("iss", issuer);
        claims.put("aud", client.getClientId());
        claims.put("sub", String.valueOf(user.getId()));
        claims.put("email", user.getEmail());
        if (user.getName() != null) claims.put("name", user.getName());
        if (nonce != null && !nonce.isBlank()) claims.put("nonce", nonce);
        return Jwts.builder()
                .header().keyId(kid).and()
                .claims(claims)
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plusSeconds(idTokenSeconds)))
                .signWith(privateKey, Jwts.SIG.RS256)
                .compact();
    }

    public record IssuedTokens(String accessToken, String idToken, long expiresIn) {}
}
