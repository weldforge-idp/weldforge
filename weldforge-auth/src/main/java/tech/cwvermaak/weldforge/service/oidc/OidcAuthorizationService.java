package tech.cwvermaak.weldforge.service.oidc;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import tech.cwvermaak.weldforge.model.OAuthAuthorizationCode;
import tech.cwvermaak.weldforge.model.OidcClient;
import tech.cwvermaak.weldforge.model.Tenant;
import tech.cwvermaak.weldforge.model.User;
import tech.cwvermaak.weldforge.repository.OAuthAuthorizationCodeRepository;
import tech.cwvermaak.weldforge.repository.OidcClientRepository;
import tech.cwvermaak.weldforge.service.audit.AuditEventTypes;
import tech.cwvermaak.weldforge.service.audit.AuditService;
import tech.cwvermaak.weldforge.service.security.AuthenticationMethods;

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
    /** A code presented twice: it left the client's control (CONF-1.2). */
    public static final String OIDC_CODE_REPLAY_DETECTED = "oidc.code.replay_detected";

    private static final SecureRandom RNG = new SecureRandom();

    /** Authorization codes are valid for 5 minutes. */
    private static final long CODE_TTL_SECONDS = 300;

    /** Standard OIDC scopes that are always permitted regardless of client registration. */
    private static final java.util.Set<String> STANDARD_OIDC_SCOPES =
            java.util.Set.of("openid", "profile", "email", "address", "phone", "offline_access");

    private final OidcClientRepository clientRepository;
    private final OAuthAuthorizationCodeRepository codeRepository;
    private final AuditService auditService;
    private final io.micrometer.core.instrument.MeterRegistry meterRegistry;
    private final tech.cwvermaak.weldforge.service.security.RefreshTokenFamilyRevoker familyRevoker;
    private final tech.cwvermaak.weldforge.repository.MfaFactorRepository mfaFactorRepository;
    private final tech.cwvermaak.weldforge.service.TenantMfaPolicyService mfaPolicyService;

    // ---- Authorize endpoint ------------------------------------------

    public record AuthorizeRequest(
            String clientId,
            String redirectUri,
            List<String> scopes,
            String state,
            String nonce,
            String codeChallenge,
            String codeChallengeMethod,
            /** OIDC max_age param — overrides client.max_authentication_age_s when smaller. */
            Integer maxAge,
            /**
             * When the authorising session was established (CONF-2.2). Recorded
             * on the code so the token endpoint, which sees no session, can emit
             * {@code auth_time}. Null when unknown — the claim is then omitted
             * rather than guessed, because a wrong authentication time is worse
             * than an absent one.
             */
            java.time.Instant authTime,
            /**
             * RFC 8176 authentication methods of the session authorising this
             * request, taken from the session token. Recorded on the code so
             * the token endpoint — which sees no session — can stamp them onto
             * the tokens it mints.
             */
            List<String> amr) {

        /** Backwards-compatible constructor for callers that don't record auth_time. */
        public AuthorizeRequest(String clientId, String redirectUri, List<String> scopes,
                                String state, String nonce,
                                String codeChallenge, String codeChallengeMethod,
                                Integer maxAge, List<String> amr) {
            this(clientId, redirectUri, scopes, state, nonce,
                    codeChallenge, codeChallengeMethod, maxAge, null, amr);
        }

        /** Backwards-compatible constructor for callers that don't know about amr. */
        public AuthorizeRequest(String clientId, String redirectUri, List<String> scopes,
                                String state, String nonce,
                                String codeChallenge, String codeChallengeMethod,
                                Integer maxAge) {
            this(clientId, redirectUri, scopes, state, nonce,
                    codeChallenge, codeChallengeMethod, maxAge, null, null);
        }

        // Backwards-compatible constructor for callers that don't know about max_age.
        public AuthorizeRequest(String clientId, String redirectUri, List<String> scopes,
                                String state, String nonce,
                                String codeChallenge, String codeChallengeMethod) {
            this(clientId, redirectUri, scopes, state, nonce,
                    codeChallenge, codeChallengeMethod, null, null, null);
        }
    }

    @Transactional
    public String issueAuthorizationCode(Tenant tenant, User user, AuthorizeRequest request) {
        OidcClient client = clientRepository.findByTenantIdAndClientId(tenant.getId(), request.clientId())
                .orElseThrow(() -> new OidcAuthorizationException("invalid_client",
                        "Unknown client_id for this tenant"));

        if (!RedirectUriMatcher.matches(client.getRedirectUriList(), request.redirectUri())) {
            throw new OidcAuthorizationException("invalid_request",
                    "redirect_uri does not match a registered URI");
        }

        // RFC 6749 §3.3 / OIDC Core §3.1.2.1: the granted scope must be
        // restricted to what the client is registered for. Enforced only when
        // the client has an explicit scope list (legacy clients registered
        // without one are left unconstrained to avoid breaking live RPs — see
        // docs/security/hardening-backlog.md to tighten this). The standard
        // OIDC scopes are always permitted.
        List<String> allowedScopes = client.getScopeList();
        if (allowedScopes != null && !allowedScopes.isEmpty()) {
            for (String requested : request.scopes()) {
                if (!STANDARD_OIDC_SCOPES.contains(requested) && !allowedScopes.contains(requested)) {
                    throw new OidcAuthorizationException("invalid_scope",
                            "Scope '" + requested + "' is not registered for this client");
                }
            }
        }

        boolean challengePresent = request.codeChallenge() != null && !request.codeChallenge().isBlank();
        if (Boolean.TRUE.equals(client.getRequirePkce())) {
            if (!challengePresent) {
                throw new OidcAuthorizationException("invalid_request",
                        "code_challenge is required for this client");
            }
            if (!"S256".equals(request.codeChallengeMethod())) {
                throw new OidcAuthorizationException("invalid_request",
                        "Only S256 code_challenge_method is supported");
            }
        } else if (!challengePresent) {
            // CONF-1.3 / RFC 9700 §2.1.1 wants PKCE on EVERY code-flow client,
            // not only public ones. New clients already default to requiring
            // it; the gap is the ones registered before that, which can still
            // run a bare code flow.
            //
            // Counted rather than refused. Flipping the flag on a live client
            // that does not send a challenge breaks its login, and there is no
            // way to know from here which those are -- so the backfill waits on
            // this meter reading zero for longer than a code TTL, at which
            // point no client is relying on the exemption.
            meterRegistry.counter("sso.oidc.pkce.missing",
                    "client_id", client.getClientId(),
                    "tenant", tenant.getSlug()).increment();
        }

        // PRD MFA-04 / SSO-05: step-up check. If the client requires MFA
        // the user must have at least one verified factor; if the client
        // sets max_authentication_age_s then the most recent factor use
        // must be within that window. Otherwise we reject with a dedicated
        // exception the controller turns into a step-up challenge.
        enforceStepUp(client, user, request.maxAge());

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
                .amr(AuthenticationMethods.toStorage(request.amr()))
                .authTime(request.authTime() == null ? null
                        : LocalDateTime.ofInstant(request.authTime(), java.time.ZoneId.systemDefault()))
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

    public record CodeExchangeResult(OidcClient client, User user, List<String> scopes, String nonce,
                                     List<String> amr, Long codeId,
                                     java.time.Instant authTime) {

        /** Backwards-compatible constructor for callers that don't record the family. */
        public CodeExchangeResult(OidcClient client, User user, List<String> scopes, String nonce,
                                  List<String> amr) {
            this(client, user, scopes, nonce, amr, null, null);
        }
    }

    /**
     * Record which refresh-token family a code exchange produced (CONF-1.2), so
     * a later replay of that code can revoke it.
     *
     * <p>Called after the token endpoint has minted the family, because until
     * then there is nothing to record. A code whose client holds no
     * {@code refresh_token} grant never gets here, which is correct: there is no
     * family, and the replay path handles null.
     */
    @Transactional
    public void recordIssuedFamily(Long codeId, java.util.UUID familyId) {
        if (codeId == null || familyId == null) return;
        codeRepository.findById(codeId).ifPresent(row -> {
            row.setIssuedFamilyId(familyId);
            codeRepository.save(row);
        });
    }

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
            // CONF-1.2 / RFC 6749 §4.1.2. Two parties presented this code, so it
            // left the legitimate client's control. Rejecting the second attempt
            // is not enough: whoever exchanged it first is holding live tokens,
            // and if that was the attacker the victim gets no signal at all --
            // their login worked. Kill the family the first exchange produced
            // and make both parties re-authenticate.
            //
            // Same reasoning, and the same REQUIRES_NEW revoker, as refresh
            // reuse detection: the throw below would otherwise roll the
            // revocation back and leave an audit event asserting a containment
            // that did not happen.
            int revoked = 0;
            if (row.getIssuedFamilyId() != null) {
                revoked = familyRevoker.revoke(row.getIssuedFamilyId(), "code_replay_detected");
            }
            log.warn("Authorization code replay: client_id={} tenant={} family={} revoked={}",
                    row.getClient().getClientId(), tenant.getSlug(),
                    row.getIssuedFamilyId(), revoked);
            auditService.log(tech.cwvermaak.weldforge.model.AuditEvent.builder()
                    .eventType(OIDC_CODE_REPLAY_DETECTED)
                    .outcome(tech.cwvermaak.weldforge.model.AuditEvent.Outcome.DENIED)
                    .tenant(tenant)
                    .actorUser(row.getUser())
                    .targetType(AuditEventTypes.TARGET_OIDC_CLIENT)
                    .targetId(row.getClient().getClientId())
                    .metadata(Map.of(
                            "family_id", String.valueOf(row.getIssuedFamilyId()),
                            "revoked_count", revoked,
                            "first_used_at", String.valueOf(row.getUsedAt()))));
            throw new OidcAuthorizationException("invalid_grant", "Authorization code already used");
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

        // Client authentication. A public client (PKCE-only, OAuth 2.1 §2.1
        // / RFC 8252) proves itself with the PKCE verifier alone and holds
        // no secret — so a code_challenge must have been bound to the code
        // at /authorize time (the verifier itself was checked just above).
        // Confidential clients present client_secret_post, compared in
        // constant time to avoid a timing oracle on the secret.
        OidcClient client = row.getClient();
        if (client.isPublicClient()) {
            if (row.getCodeChallenge() == null || row.getCodeChallenge().isBlank()) {
                throw reject("invalid_grant",
                        "PKCE (code_challenge) is required for public clients");
            }
        } else if (request.clientSecret() == null
                || !constantTimeEquals(request.clientSecret(), client.getClientSecret())) {
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
                row.getNonce(),
                AuthenticationMethods.fromStorage(row.getAmr()),
                row.getId(),
                row.getAuthTime() == null ? null
                        : row.getAuthTime().atZone(java.time.ZoneId.systemDefault()).toInstant());
    }

    // ---- Token endpoint: client credentials --------------------------

    public OidcClient verifyClientCredentials(Tenant tenant, String clientId, String clientSecret) {
        OidcClient client = clientRepository.findByTenantIdAndClientId(tenant.getId(), clientId)
                .orElseThrow(() -> reject("invalid_client", "Unknown client"));
        if (client.isPublicClient()) {
            throw reject("unauthorized_client",
                    "Public clients cannot use the client_credentials grant");
        }
        if (clientSecret == null || !constantTimeEquals(clientSecret, client.getClientSecret())) {
            throw reject("invalid_client", "Client secret mismatch");
        }
        if (!client.getGrantTypeList().contains("client_credentials")) {
            throw reject("unauthorized_client", "Client is not allowed to use client_credentials");
        }
        return client;
    }

    // ---- Token endpoint: refresh -------------------------------------

    /**
     * Verify the client presenting a refresh token.
     *
     * Confidential clients must authenticate exactly as they do for a code
     * exchange — a refresh token is a bearer credential, and letting it be
     * spent without the secret would make the secret pointless. Public
     * clients have no secret to present, so possession of the refresh token
     * is all there is; the binding check in RefreshTokenService, rotation and
     * reuse detection are what limit the damage there.
     */
    public OidcClient verifyClientForRefresh(Tenant tenant, String clientId, String clientSecret) {
        OidcClient client = clientRepository.findByTenantIdAndClientId(tenant.getId(), clientId)
                .orElseThrow(() -> reject("invalid_client", "Unknown client"));
        if (!client.getGrantTypeList().contains("refresh_token")) {
            throw reject("unauthorized_client", "Client is not allowed to use refresh_token");
        }
        if (!client.isPublicClient()
                && (clientSecret == null || !constantTimeEquals(clientSecret, client.getClientSecret()))) {
            throw reject("invalid_client", "Client secret mismatch");
        }
        return client;
    }

    // ---- Helpers -----------------------------------------------------

    /**
     * Enforce MFA step-up for a client-driven high-assurance flow.
     * Throws a {@link StepUpRequiredException} when the user needs to
     * complete a fresh factor challenge. The controller catches this and
     * redirects to the MFA challenge page instead of issuing a code.
     */
    private void enforceStepUp(OidcClient client, User user, Integer requestedMaxAge) {
        // Determine the effective max_age: OIDC max_age (request) overrides
        // client.max_authentication_age_s when smaller; the tenant default
        // applies when the client hasn't set one.
        int clientMax = client.getMaxAuthenticationAgeSeconds() != null
                ? client.getMaxAuthenticationAgeSeconds() : 0;
        int tenantDefault = 0;
        if (user.getTenant() != null) {
            var policy = mfaPolicyService.effectivePolicy(user.getTenant().getId());
            tenantDefault = policy.getDefaultStepupMaxAge() != null ? policy.getDefaultStepupMaxAge() : 0;
        }
        int effectiveMax = Math.min(
                clientMax > 0 ? clientMax : Integer.MAX_VALUE,
                tenantDefault > 0 ? tenantDefault : Integer.MAX_VALUE
        );
        if (requestedMaxAge != null && requestedMaxAge > 0) {
            effectiveMax = Math.min(effectiveMax, requestedMaxAge);
        }

        boolean clientRequiresMfa = Boolean.TRUE.equals(client.getRequireMfa());

        // Fast path — no MFA required anywhere.
        if (!clientRequiresMfa && effectiveMax == Integer.MAX_VALUE) return;

        // Find the user's verified factors.
        var factors = mfaFactorRepository.findByUserIdAndEnabledTrueAndVerifiedTrue(user.getId());
        if (factors.isEmpty()) {
            auditService.recordUserAction(AuditEventTypes.MFA_STEPUP_REQUIRED, user,
                    AuditEventTypes.TARGET_OIDC_CLIENT, client.getClientId(),
                    AuditService.meta("reason", "no_verified_factor"));
            throw new StepUpRequiredException(client.getClientId(),
                    "This application requires multi-factor authentication");
        }

        // If effectiveMax is set, the most recent factor use must be within the window.
        if (effectiveMax != Integer.MAX_VALUE) {
            LocalDateTime cutoff = LocalDateTime.now().minusSeconds(effectiveMax);
            boolean fresh = factors.stream()
                    .map(f -> f.getLastUsedAt())
                    .filter(java.util.Objects::nonNull)
                    .anyMatch(t -> t.isAfter(cutoff));
            if (!fresh) {
                auditService.recordUserAction(AuditEventTypes.MFA_STEPUP_REQUIRED, user,
                        AuditEventTypes.TARGET_OIDC_CLIENT, client.getClientId(),
                        AuditService.meta("reason", "stale_factor", "max_age", effectiveMax));
                throw new StepUpRequiredException(client.getClientId(),
                        "Re-authentication required for this application");
            }
        }
    }

    private OidcAuthorizationException reject(String code, String message) {
        log.warn("OIDC reject code={} reason={}", code, message);
        // Audit the failure on the way out so the controller doesn't have to.
        auditService.log(tech.cwvermaak.weldforge.model.AuditEvent.builder()
                .eventType(OIDC_CODE_REJECTED)
                .outcome(tech.cwvermaak.weldforge.model.AuditEvent.Outcome.DENIED)
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

    /** Constant-time string comparison — avoids a timing oracle on the client secret. */
    private static boolean constantTimeEquals(String a, String b) {
        if (a == null || b == null) return false;
        return MessageDigest.isEqual(
                a.getBytes(StandardCharsets.UTF_8),
                b.getBytes(StandardCharsets.UTF_8));
    }
}
