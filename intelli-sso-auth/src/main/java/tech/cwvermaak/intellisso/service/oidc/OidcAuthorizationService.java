package tech.cwvermaak.intellisso.service.oidc;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import tech.cwvermaak.intellisso.model.OAuthAuthorizationCode;
import tech.cwvermaak.intellisso.model.OidcClient;
import tech.cwvermaak.intellisso.model.Tenant;
import tech.cwvermaak.intellisso.model.User;
import tech.cwvermaak.intellisso.repository.OAuthAuthorizationCodeRepository;
import tech.cwvermaak.intellisso.repository.OidcClientRepository;
import tech.cwvermaak.intellisso.service.audit.AuditEventTypes;
import tech.cwvermaak.intellisso.service.audit.AuditService;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.List;
import java.util.Map;

/**
 * The OIDC authorization endpoint logic — split out from the controller so
 * it can be unit-tested without spinning up MockMvc.
 *
 * Two flows handled:
 *
 * <h3>Authorization code with PKCE</h3>
 * <ol>
 *   <li>{@link #issueAuthorizationCode} — called from the controller after
 *       the user is authenticated. Validates the client, redirect URI and
 *       PKCE parameters, persists a hashed code, and returns the raw code
 *       for the redirect.</li>
 *   <li>{@link #exchangeCode} — called from the token endpoint. Validates
 *       the code (existence, expiry, single-use), the redirect URI match,
 *       and the PKCE verifier, then deletes the code as used.</li>
 * </ol>
 *
 * <h3>Client credentials</h3>
 * {@link #verifyClientCredentials} — pure secret check, returns the resolved
 * client. The token controller takes it from there.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class OidcAuthorizationService {

    public static final String OIDC_CODE_ISSUED   = "oidc.code.issued";
    public static final String OIDC_CODE_EXCHANGED = "oidc.code.exchanged";
    public static final String OIDC_CODE_REJECTED = "oidc.code.rejected";

    private static final SecureRandom RNG = new SecureRandom();

    /** Authorization codes are valid for 5 minutes. */
    private static final long CODE_TTL_SECONDS = 300;

    private final OidcClientRepository clientRepository;
    private final OAuthAuthorizationCodeRepository codeRepository;
    private final AuditService auditService;

    // ---- Authorize endpoint ------------------------------------------

    public record AuthorizeRequest(
            String clientId,
            String redirectUri,
            List<String> scopes,
            String state,
            String nonce,
            String codeChallenge,
            String codeChallengeMethod) {}

    @Transactional
    public String issueAuthorizationCode(Tenant tenant, User user, AuthorizeRequest request) {
        OidcClient client = clientRepository.findByTenantIdAndClientId(tenant.getId(), request.clientId())
                .orElseThrow(() -> new OidcAuthorizationException("invalid_client",
                        "Unknown client_id for this tenant"));

        if (!client.getRedirectUriList().contains(request.redirectUri())) {
            throw new OidcAuthorizationException("invalid_request",
                    "redirect_uri does not match a registered URI");
        }

        if (Boolean.TRUE.equals(client.getRequirePkce())) {
            if (request.codeChallenge() == null || request.codeChallenge().isBlank()) {
                throw new OidcAuthorizationException("invalid_request",
                        "code_challenge is required for this client");
            }
            if (!"S256".equals(request.codeChallengeMethod())) {
                throw new OidcAuthorizationException("invalid_request",
                        "Only S256 code_challenge_method is supported");
            }
        }

        String rawCode = generateCode();
        OAuthAuthorizationCode row = OAuthAuthorizationCode.builder()
                .codeHash(sha256(rawCode))
                .client(client)
                .tenant(tenant)
                .user(user)
                .redirectUri(request.redirectUri())
                .scopes(String.join(" ", request.scopes()))
                .nonce(request.nonce())
                .codeChallenge(request.codeChallenge())
                .codeChallengeMethod(request.codeChallengeMethod())
                .expiresAt(LocalDateTime.now().plusSeconds(CODE_TTL_SECONDS))
                .build();
        codeRepository.save(row);

        auditService.recordUserAction(OIDC_CODE_ISSUED, user,
                AuditEventTypes.TARGET_USER, String.valueOf(user.getId()),
                AuditService.meta("client_id", client.getClientId(), "tenant", tenant.getSlug()));
        return rawCode;
    }

    // ---- Token endpoint: code exchange -------------------------------

    public record CodeExchangeRequest(
            String code,
            String clientId,
            String clientSecret,
            String redirectUri,
            String codeVerifier) {}

    public record CodeExchangeResult(OidcClient client, User user, List<String> scopes, String nonce) {}

    @Transactional
    public CodeExchangeResult exchangeCode(Tenant tenant, CodeExchangeRequest request) {
        OAuthAuthorizationCode row = codeRepository.findByCodeHash(sha256(request.code()))
                .orElseThrow(() -> reject("invalid_grant", "Unknown authorization code"));

        // The code is bound to a single tenant — and a single client — at
        // mint time. We re-check both here so that even if a code somehow
        // leaked, it could not be redeemed against a different relying party.
        if (!row.getTenant().getId().equals(tenant.getId())) {
            throw reject("invalid_grant", "Code does not belong to this tenant");
        }
        if (!row.getClient().getClientId().equals(request.clientId())) {
            throw reject("invalid_grant", "Code was issued to a different client");
        }
        if (row.getUsedAt() != null) {
            throw reject("invalid_grant", "Authorization code already used");
        }
        if (LocalDateTime.now().isAfter(row.getExpiresAt())) {
            throw reject("invalid_grant", "Authorization code expired");
        }
        if (!row.getRedirectUri().equals(request.redirectUri())) {
            throw reject("invalid_grant", "redirect_uri mismatch");
        }

        // PKCE check.
        if (row.getCodeChallenge() != null) {
            if (request.codeVerifier() == null || request.codeVerifier().isBlank()) {
                throw reject("invalid_grant", "code_verifier required");
            }
            String expected = base64UrlSha256(request.codeVerifier());
            if (!expected.equals(row.getCodeChallenge())) {
                throw reject("invalid_grant", "PKCE verification failed");
            }
        }

        // Confidential client check (require client_secret if PKCE didn't
        // already cover it). For pure public clients with PKCE, the secret
        // is optional — but we keep it strict for now.
        if (request.clientSecret() == null || !request.clientSecret().equals(row.getClient().getClientSecret())) {
            throw reject("invalid_client", "Client secret mismatch");
        }

        row.setUsedAt(LocalDateTime.now());
        codeRepository.save(row);

        auditService.recordUserAction(OIDC_CODE_EXCHANGED, row.getUser(),
                AuditEventTypes.TARGET_USER, String.valueOf(row.getUser().getId()),
                AuditService.meta("client_id", row.getClient().getClientId(),
                                  "tenant", tenant.getSlug()));

        return new CodeExchangeResult(
                row.getClient(),
                row.getUser(),
                List.of(row.getScopes().split("\\s+")),
                row.getNonce());
    }

    // ---- Token endpoint: client credentials --------------------------

    public OidcClient verifyClientCredentials(Tenant tenant, String clientId, String clientSecret) {
        OidcClient client = clientRepository.findByTenantIdAndClientId(tenant.getId(), clientId)
                .orElseThrow(() -> reject("invalid_client", "Unknown client"));
        if (clientSecret == null || !clientSecret.equals(client.getClientSecret())) {
            throw reject("invalid_client", "Client secret mismatch");
        }
        if (!client.getGrantTypeList().contains("client_credentials")) {
            throw reject("unauthorized_client", "Client is not allowed to use client_credentials");
        }
        return client;
    }

    // ---- Helpers -----------------------------------------------------

    private OidcAuthorizationException reject(String code, String message) {
        log.warn("OIDC reject code={} reason={}", code, message);
        // Audit the failure on the way out so the controller doesn't have to.
        auditService.log(tech.cwvermaak.intellisso.model.AuditEvent.builder()
                .eventType(OIDC_CODE_REJECTED)
                .outcome(tech.cwvermaak.intellisso.model.AuditEvent.Outcome.DENIED)
                .metadata(Map.of("error", code, "reason", message)));
        return new OidcAuthorizationException(code, message);
    }

    private static String generateCode() {
        byte[] buf = new byte[32];
        RNG.nextBytes(buf);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(buf);
    }

    static String sha256(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            return Base64.getUrlEncoder().withoutPadding()
                    .encodeToString(md.digest(input.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    /** Public so BDD step definitions can compute the same challenge as a real client. */
    public static String base64UrlSha256(String verifier) {
        return sha256(verifier);
    }
}
