package tech.cwvermaak.weldforge.service.oidc;

import jakarta.persistence.EntityNotFoundException;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import tech.cwvermaak.weldforge.config.tenant.TenantAccessor;
import tech.cwvermaak.weldforge.model.OidcClient;
import tech.cwvermaak.weldforge.model.Tenant;
import tech.cwvermaak.weldforge.model.dto.OidcClientDto;
import tech.cwvermaak.weldforge.repository.OidcClientRepository;
import tech.cwvermaak.weldforge.service.audit.AuditEventTypes;
import tech.cwvermaak.weldforge.service.audit.AuditService;

import java.net.URI;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.List;
import java.util.UUID;

/**
 * Tenant-scoped admin operations for OIDC relying parties. The service is
 * the only place that talks to {@link OidcClientRepository}, so every
 * read and write is automatically forced through {@link TenantAccessor}.
 *
 * Client secrets are generated server-side, AES-GCM encrypted at rest,
 * and surfaced in plaintext exactly once on create or rotate. Subsequent
 * GETs never return the secret.
 */
@Service
@RequiredArgsConstructor
public class OidcClientService {

    private static final SecureRandom RNG = new SecureRandom();

    private final TenantAccessor tenantAccessor;
    private final OidcClientRepository repository;
    /**
     * Admin create/rotate/delete were never audited. When a client landed in
     * the wrong tenant on 2026-09-11 there was no record of who created it,
     * in which tenant, or through which selector.
     */
    private final AuditService auditService;

    public List<OidcClientDto> list() {
        tenantAccessor.requireAnyAdmin();
        Long tid = tenantAccessor.requireTenantId();
        return repository.findByTenantId(tid).stream()
                .map(c -> toDto(c, false))
                .toList();
    }

    @Transactional
    public OidcClientDto create(OidcClientDto dto) {
        tenantAccessor.requireTenantAdmin();
        return createInternal(dto);
    }

    /**
     * Register a client without an admin session, for RFC 7591 dynamic
     * registration.
     *
     * <p>{@link #create} demands a tenant admin, which an unauthenticated DCR
     * POST can never be — so the registration endpoint answered 403 to the
     * only caller it exists for, while discovery advertised it. Whether that
     * endpoint is open at all is a deployment decision made by the caller of
     * this method, not here.
     *
     * <p>Every validation the admin path runs still runs. A client that
     * registers itself is no less able to register itself unusably.
     */
    @Transactional
    public OidcClientDto createForDynamicRegistration(OidcClientDto dto) {
        return createInternal(dto);
    }

    private OidcClientDto createInternal(OidcClientDto dto) {
        Tenant tenant = tenantAccessor.requireTenant();
        require(dto.getRedirectUris(), "redirectUris");
        require(dto.getScopes(),       "scopes");
        require(dto.getGrantTypes(),   "grantTypes");
        validateRedirectUris(dto.getRedirectUris());
        validateWebOrigins(dto.getWebOrigins());

        String clientId = dto.getClientId() != null && !dto.getClientId().isBlank()
                ? dto.getClientId()
                : "wf_client_" + UUID.randomUUID().toString().replace("-", "");
        String clientSecret = generateSecret();

        if (repository.findByTenantIdAndClientId(tenant.getId(), clientId).isPresent()) {
            throw new IllegalArgumentException("clientId already in use for this tenant");
        }

        // A client is public when it says so explicitly or declares the
        // 'none' token-endpoint auth method (OAuth 2.1 / RFC 8252 — browser
        // SPAs and native apps). Public clients are PKCE-only: there is no
        // secret to fall back on, so require_pkce is forced on and the
        // generated secret is never surfaced to the caller.
        boolean isPublic = Boolean.TRUE.equals(dto.getPublicClient())
                || "none".equalsIgnoreCase(dto.getTokenEndpointAuthMethod());
        boolean requirePkce = isPublic
                || dto.getRequirePkce() == null || dto.getRequirePkce();

        // A browser client with no web origin registers fine and then cannot
        // sign anyone in, with no error the developer can see. Refuse it here.
        requireWebOriginForBrowserClients(isPublic, dto.getRedirectUris(), dto.getWebOrigins());

        OidcClient client = OidcClient.builder()
                .tenant(tenant)
                .clientId(clientId)
                .clientSecret(clientSecret)
                .name(dto.getName())
                .redirectUris(joinCsv(dto.getRedirectUris()))
                .postLogoutRedirectUris(joinCsv(dto.getPostLogoutRedirectUris()))
                .webOrigins(joinCsv(dto.getWebOrigins()))
                .scopes(joinCsv(dto.getScopes()))
                .grantTypes(joinCsv(dto.getGrantTypes()))
                .requirePkce(requirePkce)
                .requireMfa(Boolean.TRUE.equals(dto.getRequireMfa()))
                .maxAuthenticationAgeSeconds(dto.getMaxAuthenticationAgeSeconds() != null
                        ? dto.getMaxAuthenticationAgeSeconds() : 0)
                .publicClient(isPublic)
                // CONF-4.1/4.3: client_secret_basic is RFC 7591's default and what
                // most libraries reach for. The token endpoint now accepts it,
                // so registration can finally report it truthfully -- until
                // this it advertised Basic and the server could only parse a
                // form body, which is the mismatch CONF-4.3 was raised for.
                .tokenEndpointAuthMethod(isPublic ? "none" : "client_secret_basic")
                // Accepted at registration, not only on a later edit. Until
                // this it was silently dropped: the field was on the DTO and
                // in the update path, so a caller sending it at create got a
                // 200 and a client that inherited the default anyway.
                .refreshTokenTtlSeconds(requirePositiveTtl(dto.getRefreshTokenTtlSeconds()))
                .branding(dto.getBranding())
                .build();
        OidcClient saved = repository.save(client);
        auditService.recordAdmin(AuditEventTypes.OIDC_CLIENT_CREATE, null,
                AuditEventTypes.TARGET_OIDC_CLIENT, saved.getClientId(),
                AuditService.meta("tenant", tenant.getSlug(), "name", saved.getName(),
                        "public_client", isPublic));

        OidcClientDto out = toDto(saved, true);
        // A public client has no usable secret — never hand one back.
        out.setClientSecret(isPublic ? null : clientSecret); // confidential: shown once
        return out;
    }

    /**
     * Replace a client's configuration in place.
     *
     * <p>Until this existed the only way to correct a registration was to
     * delete and recreate it, which mints a new {@code client_secret} and
     * therefore breaks every deployed consumer until each is updated. That is
     * not a theoretical cost: {@code keycrypt-web} was registered with no
     * {@code webOrigins} and its sign-in was inert for two days, and its
     * {@code post_logout_redirect_uris} is still empty, because neither could
     * be fixed without a rotation nobody wanted to schedule.
     *
     * <p>What this deliberately does <em>not</em> touch:
     * <ul>
     *   <li><b>{@code clientId}</b> — it is the {@code aud} of every token
     *       already issued and the identifier every consumer has configured.
     *       Renaming it is indistinguishable from creating a different client,
     *       so callers must do exactly that.</li>
     *   <li><b>{@code clientSecret}</b> — {@link #rotateSecret(Long)} owns it.
     *       Folding rotation into a general update would make every
     *       configuration edit a potential outage.</li>
     *   <li><b>{@code publicClient}</b> — flipping confidential to public
     *       would silently strip secret authentication from a live client,
     *       and public to confidential would hand out a secret the app has
     *       no way to use. Either is a new client.</li>
     * </ul>
     *
     * <p>Null fields are left unchanged, so a caller can send only what it
     * means to alter. An empty list is a real value and clears the list —
     * that is how a wrongly-registered origin gets removed.
     */
    @Transactional
    public OidcClientDto update(Long id, OidcClientDto dto) {
        tenantAccessor.requireTenantAdmin();
        Long tid = tenantAccessor.requireTenantId();
        OidcClient client = repository.findByIdAndTenantId(id, tid)
                .orElseThrow(() -> new EntityNotFoundException("OIDC client " + id + " not found"));
        return apply(client, dto);
    }

    /**
     * Update a client by primary key, without an admin session.
     *
     * <p>For the RFC 7592 endpoint, where the registration access token has
     * already proved the caller may manage THIS client — the same reason
     * {@link #deleteById(Long)} exists. The caller must have authorised the
     * client itself; this method does not re-check.
     *
     * <p>Every validation the admin path runs still runs here. A dynamically
     * registered client is no less able to break itself by clearing its own
     * web origins.
     */
    @Transactional
    public OidcClientDto updateById(Long id, OidcClientDto dto) {
        OidcClient client = repository.findById(id)
                .orElseThrow(() -> new EntityNotFoundException("OIDC client " + id + " not found"));
        return apply(client, dto);
    }

    private OidcClientDto apply(OidcClient client, OidcClientDto dto) {
        rejectImmutable("clientId", dto.getClientId(), client.getClientId());
        rejectImmutable("publicClient", dto.getPublicClient(), client.getPublicClient());
        if (dto.getClientSecret() != null) {
            throw new IllegalArgumentException(
                    "clientSecret cannot be set here; use POST /{id}/rotate-secret");
        }

        List<String> redirectUris = dto.getRedirectUris() != null
                ? dto.getRedirectUris() : client.getRedirectUriList();
        List<String> webOrigins = dto.getWebOrigins() != null
                ? dto.getWebOrigins() : client.getWebOriginList();

        if (dto.getRedirectUris() != null) {
            require(dto.getRedirectUris(), "redirectUris");
            validateRedirectUris(dto.getRedirectUris());
        }
        if (dto.getWebOrigins() != null) {
            validateWebOrigins(dto.getWebOrigins());
        }
        if (dto.getPostLogoutRedirectUris() != null) {
            validateRedirectUris(dto.getPostLogoutRedirectUris());
        }
        if (dto.getScopes() != null) {
            require(dto.getScopes(), "scopes");
        }
        if (dto.getGrantTypes() != null) {
            require(dto.getGrantTypes(), "grantTypes");
        }
        requirePositiveTtl(dto.getRefreshTokenTtlSeconds());

        // The same guard as create, against the merged result rather than the
        // payload: clearing the origins of a browser client is exactly as
        // breaking as registering it without them in the first place.
        requireWebOriginForBrowserClients(client.isPublicClient(), redirectUris, webOrigins);

        if (dto.getName() != null)                   client.setName(dto.getName());
        if (dto.getRedirectUris() != null)           client.setRedirectUris(joinCsv(dto.getRedirectUris()));
        if (dto.getPostLogoutRedirectUris() != null) client.setPostLogoutRedirectUris(joinCsv(dto.getPostLogoutRedirectUris()));
        if (dto.getWebOrigins() != null)             client.setWebOrigins(joinCsv(dto.getWebOrigins()));
        if (dto.getScopes() != null)                 client.setScopes(joinCsv(dto.getScopes()));
        if (dto.getGrantTypes() != null)             client.setGrantTypes(joinCsv(dto.getGrantTypes()));
        if (dto.getRequireMfa() != null)             client.setRequireMfa(dto.getRequireMfa());
        if (dto.getMaxAuthenticationAgeSeconds() != null) {
            client.setMaxAuthenticationAgeSeconds(dto.getMaxAuthenticationAgeSeconds());
        }
        if (dto.getRefreshTokenTtlSeconds() != null) {
            client.setRefreshTokenTtlSeconds(dto.getRefreshTokenTtlSeconds());
        }
        // An empty object is a real value: it clears the override and returns
        // the client to the tenant's branding. Null is "leave alone".
        if (dto.getBranding() != null) {
            client.setBranding(dto.getBranding().isEmpty() ? null : dto.getBranding());
        }
        // A public client is PKCE-only and stays that way; for a confidential
        // client the flag is the caller's to set.
        if (dto.getRequirePkce() != null && !client.isPublicClient()) {
            client.setRequirePkce(dto.getRequirePkce());
        }

        auditService.recordAdmin(AuditEventTypes.OIDC_CLIENT_UPDATE, null,
                AuditEventTypes.TARGET_OIDC_CLIENT, client.getClientId(),
                AuditService.meta("tenant", client.getTenant().getSlug(),
                        "fields", changedFieldNames(dto)));

        return toDto(client, true);
    }

    /**
     * A refresh TTL must be positive or absent. Shared by create and update
     * so the two cannot disagree about what is acceptable.
     *
     * <p>Zero is not "inherit" here, deliberately: null is. Zero would mean a
     * token that expires the instant it is minted, and accepting it silently
     * would be worse than refusing it.
     */
    private static Integer requirePositiveTtl(Integer seconds) {
        if (seconds != null && seconds <= 0) {
            throw new IllegalArgumentException(
                    "refreshTokenTtlSeconds must be positive; omit it to inherit the tenant or application default");
        }
        return seconds;
    }

    /** Refuse a field that may be read back but never altered. */
    private static void rejectImmutable(String field, Object supplied, Object current) {
        if (supplied != null && !supplied.equals(current)) {
            throw new IllegalArgumentException(
                    field + " cannot be changed on an existing client; create a new one instead");
        }
    }

    /** Names of the fields this request actually carries, for the audit row. */
    private static String changedFieldNames(OidcClientDto d) {
        List<String> names = new java.util.ArrayList<>();
        if (d.getName() != null)                       names.add("name");
        if (d.getRedirectUris() != null)               names.add("redirectUris");
        if (d.getPostLogoutRedirectUris() != null)     names.add("postLogoutRedirectUris");
        if (d.getWebOrigins() != null)                 names.add("webOrigins");
        if (d.getScopes() != null)                     names.add("scopes");
        if (d.getGrantTypes() != null)                 names.add("grantTypes");
        if (d.getRequireMfa() != null)                 names.add("requireMfa");
        if (d.getMaxAuthenticationAgeSeconds() != null) names.add("maxAuthenticationAgeSeconds");
        if (d.getRefreshTokenTtlSeconds() != null)     names.add("refreshTokenTtlSeconds");
        if (d.getRequirePkce() != null)                names.add("requirePkce");
        if (d.getBranding() != null)                   names.add("branding");
        return String.join(",", names);
    }

    @Transactional
    public OidcClientDto rotateSecret(Long id) {
        tenantAccessor.requireTenantAdmin();
        Long tid = tenantAccessor.requireTenantId();
        OidcClient client = repository.findByIdAndTenantId(id, tid)
                .orElseThrow(() -> new EntityNotFoundException("OIDC client " + id + " not found"));
        if (client.isPublicClient()) {
            throw new IllegalArgumentException(
                    "Public clients authenticate with PKCE and have no secret to rotate");
        }
        String newSecret = generateSecret();
        client.setClientSecret(newSecret);
        auditService.recordAdmin(AuditEventTypes.OIDC_CLIENT_ROTATE_SECRET, null,
                AuditEventTypes.TARGET_OIDC_CLIENT, client.getClientId(),
                AuditService.meta("tenant", client.getTenant().getSlug()));
        OidcClientDto out = toDto(client, true);
        out.setClientSecret(newSecret);
        return out;
    }

    @Transactional
    public void delete(Long id) {
        tenantAccessor.requireTenantAdmin();
        Long tid = tenantAccessor.requireTenantId();
        OidcClient client = repository.findByIdAndTenantId(id, tid)
                .orElseThrow(() -> new EntityNotFoundException("OIDC client " + id + " not found"));
        repository.delete(client);
        auditService.recordAdmin(AuditEventTypes.OIDC_CLIENT_DELETE, null,
                AuditEventTypes.TARGET_OIDC_CLIENT, client.getClientId(),
                AuditService.meta("tenant", client.getTenant().getSlug(), "name", client.getName()));
    }

    // ---- Helpers ----------------------------------------------------

    static OidcClientDto toDto(OidcClient c, boolean includeSecretFlag) {
        return OidcClientDto.builder()
                .id(c.getId())
                .tenantId(c.getTenant().getId())
                .clientId(c.getClientId())
                .name(c.getName())
                .redirectUris(c.getRedirectUriList())
                .scopes(c.getScopeList())
                .grantTypes(c.getGrantTypeList())
                .requirePkce(c.getRequirePkce())
                .requireMfa(c.getRequireMfa())
                .maxAuthenticationAgeSeconds(c.getMaxAuthenticationAgeSeconds())
                .webOrigins(c.getWebOriginList())
                .postLogoutRedirectUris(c.getPostLogoutRedirectUriList())
                .publicClient(c.getPublicClient())
                .tokenEndpointAuthMethod(c.getTokenEndpointAuthMethod())
                .refreshTokenTtlSeconds(c.getRefreshTokenTtlSeconds())
                .branding(c.getBranding())
                // clientSecret intentionally null unless caller overrides.
                .build();
    }

    private static String generateSecret() {
        byte[] buf = new byte[32];
        RNG.nextBytes(buf);
        return "wfs_" + Base64.getUrlEncoder().withoutPadding().encodeToString(buf);
    }

    /** Join a list into the space-separated CSV the entity stores; null/empty → "". */
    private static String joinCsv(List<String> values) {
        return values == null ? "" : String.join(" ", values);
    }

    /**
     * Validate registered web (CORS) origins. Each must be a bare origin —
     * {@code scheme://host[:port]} with no path/query/fragment. {@code https}
     * is always allowed; plain {@code http} is permitted only for loopback
     * hosts (localhost / 127.0.0.1 / ::1) so local development works without
     * opening the door to plaintext origins in production.
     */
    /**
     * A public client that signs in from a browser is unusable without a web
     * origin, so refuse to register one rather than let it fail silently later.
     *
     * <p>A browser client runs the whole flow with {@code fetch}: discovery,
     * JWKS, and the PKCE token exchange. Those are cross-origin to the tenant's
     * OIDC endpoints, and the allow-list is built from the tenant's clients'
     * {@code webOrigins}. Register none and every one of those calls is refused
     * with a CORS 403 — and because the browser reports a blocked fetch as a
     * generic network failure, the usual symptom is a sign-in button that does
     * nothing at all, with no error anywhere the developer is looking.
     *
     * <p>That happened on 2026-09-20: KeyCrypt's SPA client was registered
     * without one, and its sign-in button was inert for two days before anyone
     * traced it to CORS.
     *
     * <p><strong>Native clients are deliberately exempt.</strong> RFC 8252 apps
     * redirect to a loopback address or a private-use URI scheme, make no
     * cross-origin browser calls, and correctly have no origin — production
     * holds two such clients today. Only a redirect to a real http(s) host
     * implies a browser, and only then is the origin required.
     */
    static void requireWebOriginForBrowserClients(boolean isPublic,
                                                  List<String> redirectUris,
                                                  List<String> webOrigins) {
        if (!isPublic) return;                       // confidential: server-side, no CORS
        boolean hasOrigin = webOrigins != null
                && webOrigins.stream().anyMatch(o -> o != null && !o.isBlank());
        if (hasOrigin || redirectUris == null) return;

        for (String raw : redirectUris) {
            if (raw == null || raw.isBlank()) continue;
            URI uri;
            try {
                uri = URI.create(raw.trim());
            } catch (IllegalArgumentException e) {
                continue;                            // validateRedirectUris reports this
            }
            String scheme = uri.getScheme();
            if (scheme == null) continue;
            if (!"http".equalsIgnoreCase(scheme) && !"https".equalsIgnoreCase(scheme)) {
                continue;                            // private-use scheme: native app
            }
            String host = uri.getHost();
            if (host == null || isLoopback(host)) continue;   // loopback: native app

            throw new IllegalArgumentException(
                    "webOrigins is required for a public client with a browser redirect URI ("
                    + raw.trim() + "). Without it every cross-origin call from the browser — "
                    + "discovery, JWKS and the token exchange — is refused by CORS, and the "
                    + "usual symptom is a sign-in button that silently does nothing. "
                    + "Set webOrigins to the site's origin, e.g. "
                    + originOf(uri)
                    + ". Native apps using a loopback or private-use redirect do not need it.");
        }
    }

    private static boolean isLoopback(String host) {
        String h = host.startsWith("[") && host.endsWith("]")
                ? host.substring(1, host.length() - 1)
                : host;
        return "localhost".equalsIgnoreCase(h) || "127.0.0.1".equals(h) || "::1".equals(h);
    }

    /** scheme://host[:port] for the message, so the fix can be pasted straight in. */
    private static String originOf(URI uri) {
        return uri.getScheme() + "://" + uri.getHost()
             + (uri.getPort() == -1 ? "" : ":" + uri.getPort());
    }

    private static void validateWebOrigins(List<String> origins) {
        if (origins == null) return;
        for (String raw : origins) {
            if (raw == null || raw.isBlank()) continue;
            String o = raw.trim();
            URI uri;
            try {
                uri = URI.create(o);
            } catch (IllegalArgumentException e) {
                throw new IllegalArgumentException("Invalid web origin: " + o);
            }
            String scheme = uri.getScheme();
            String host = uri.getHost();
            boolean hasPathOrQuery = (uri.getPath() != null && !uri.getPath().isBlank())
                    || uri.getQuery() != null || uri.getFragment() != null;
            if (scheme == null || host == null || hasPathOrQuery) {
                throw new IllegalArgumentException(
                        "Web origin must be scheme://host[:port] with no path: " + o);
            }
            boolean https = "https".equalsIgnoreCase(scheme);
            boolean httpLoopback = "http".equalsIgnoreCase(scheme) && isLoopbackHost(host);
            if (!https && !httpLoopback) {
                throw new IllegalArgumentException(
                        "Web origin must use https (plain http is allowed only for "
                        + "localhost / 127.0.0.1): " + o);
            }
        }
    }

    /**
     * Validate registered redirect URIs (B-OIDC-4 / RFC 9700 §2.1, RFC 8252).
     * Each must be absolute and carry no fragment; plain {@code http} is allowed
     * only for loopback hosts. {@code https} and custom app schemes (native
     * deep links) are permitted.
     */
    private static void validateRedirectUris(List<String> uris) {
        if (uris == null) return;
        for (String raw : uris) {
            if (raw == null || raw.isBlank()) continue;
            String u = raw.trim();
            URI uri;
            try {
                uri = URI.create(u);
            } catch (IllegalArgumentException e) {
                throw new IllegalArgumentException("Invalid redirect_uri: " + u);
            }
            if (!uri.isAbsolute() || uri.getScheme() == null) {
                throw new IllegalArgumentException("redirect_uri must be absolute: " + u);
            }
            if (uri.getFragment() != null) {
                throw new IllegalArgumentException("redirect_uri must not contain a fragment: " + u);
            }
            if ("http".equalsIgnoreCase(uri.getScheme()) && !isLoopbackHost(uri.getHost())) {
                throw new IllegalArgumentException(
                        "redirect_uri must use https (plain http is allowed only for loopback): " + u);
            }
        }
    }

    private static boolean isLoopbackHost(String host) {
        return "localhost".equalsIgnoreCase(host)
                || "127.0.0.1".equals(host)
                || "::1".equals(host) || "[::1]".equals(host);
    }

    private static void require(List<String> v, String field) {
        if (v == null || v.isEmpty()) throw new IllegalArgumentException(field + " is required");
    }

    // ---- RFC 7592 registration access tokens (CONF-4.3) ---------------

    /**
     * Mint and store a registration access token for a dynamically-registered
     * client, returning the raw value for the registration response.
     *
     * <p>Only the hash is persisted, for the same reason refresh tokens are
     * hashed: this is a bearer credential that can delete a working client
     * registration, so a database dump must not be enough to take one over.
     * The raw value is shown exactly once and cannot be recovered afterwards.
     */
    @Transactional
    public String issueRegistrationAccessToken(Long tenantId, String clientId) {
        byte[] buf = new byte[32];
        RNG.nextBytes(buf);
        String raw = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(buf);

        OidcClient client = repository.findByTenantIdAndClientId(tenantId, clientId)
                .orElseThrow(() -> new IllegalStateException(
                        "Client vanished between creation and token issue: " + clientId));
        client.setRegistrationAccessTokenHash(hashRegistrationToken(raw));
        repository.save(client);
        return raw;
    }

    /** Delete a client by primary key. Used by the RFC 7592 delete endpoint. */
    @Transactional
    public void deleteById(Long id) {
        repository.deleteById(id);
    }

    /**
     * Hash a registration access token for storage or comparison.
     *
     * <p>Plain SHA-256 rather than BCrypt, matching how refresh tokens and
     * authorization codes are stored here. These are 256-bit random values, not
     * passwords: there is no dictionary to attack, so a slow KDF would buy
     * nothing and cost latency on every management call.
     */
    public static String hashRegistrationToken(String raw) {
        try {
            java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-256");
            return java.util.Base64.getUrlEncoder().withoutPadding()
                    .encodeToString(md.digest(raw.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
        } catch (Exception e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }
}
