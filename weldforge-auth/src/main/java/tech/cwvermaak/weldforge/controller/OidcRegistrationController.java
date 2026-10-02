package tech.cwvermaak.weldforge.controller;

import jakarta.persistence.EntityNotFoundException;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import tech.cwvermaak.weldforge.model.OidcClient;
import tech.cwvermaak.weldforge.model.Tenant;
import tech.cwvermaak.weldforge.repository.OidcClientRepository;
import tech.cwvermaak.weldforge.model.dto.OidcClientDto;
import tech.cwvermaak.weldforge.repository.TenantRepository;
import tech.cwvermaak.weldforge.service.audit.AuditEventTypes;
import tech.cwvermaak.weldforge.service.audit.AuditService;
import tech.cwvermaak.weldforge.service.oidc.OidcClientService;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * RFC 7591 — Dynamic Client Registration endpoint. Allows relying parties
 * to register themselves at runtime without prior admin configuration.
 *
 * <p>Registration itself is public, because the RFC's design assumes open
 * registration. <b>Whether it should stay that way is an open product
 * question</b> — open registration is a reasonable choice for a self-service
 * product and an abuse vector for an enterprise one — and is tracked in
 * {@code docs/product/standards-conformance-backlog.md} under CONF-4.3. This
 * class does not settle it.
 *
 * <p>What it does settle is the management half (RFC 7592). Every registration
 * response has always carried a {@code registration_client_uri}, as RFC 7591
 * §3.2.1 requires, but nothing was ever served there — the success response
 * handed clients a 404. Libraries that follow that URI on startup to confirm
 * their registration took therefore saw a broken registration. The endpoints
 * now exist, authorised by a registration access token issued at the same time.
 */
@RestController
@RequiredArgsConstructor
@Slf4j
public class OidcRegistrationController {

    /**
     * Whether this deployment accepts RFC 7591 dynamic registration.
     *
     * <p>Default OFF. Registration previously answered 403 to every
     * unauthenticated caller because it required a tenant admin, so off is
     * the behaviour that already shipped — the difference is that it is now
     * a stated decision with a legible refusal, and discovery stops
     * advertising an endpoint nobody can use.
     *
     * <p>Turn it on for a self-hosted deployment, or to run the Dynamic OP
     * conformance profile. On the hosted service it stays off: anyone on the
     * internet could otherwise create clients in a tenant.
     */
    @org.springframework.beans.factory.annotation.Value(
            "${app.security.oidc.dynamic-registration-enabled:false}")
    private boolean dynamicRegistrationEnabled;

    private final OidcClientService oidcClientService;
    private final OidcClientRepository oidcClientRepository;
    private final TenantRepository tenantRepository;
    private final AuditService auditService;

    /**
     * POST /t/{slug}/oauth2/register
     *
     * Accepts an RFC 7591 client registration request and returns the
     * registered client metadata including the generated credentials.
     */
    @PostMapping(value = "/t/{slug}/oauth2/register",
                 consumes = MediaType.APPLICATION_JSON_VALUE,
                 produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Map<String, Object>> register(
            @PathVariable String slug,
            @RequestBody Map<String, Object> registrationRequest,
            HttpServletRequest request) {

        if (!dynamicRegistrationEnabled) {
            // A refusal that names itself. The old 403 came from an admin
            // check deep in the service and read as "you are not an admin",
            // which is true and useless: no DCR caller ever is one.
            throw new tech.cwvermaak.weldforge.service.oidc.OidcAuthorizationException(
                    "invalid_request",
                    "Dynamic client registration is not enabled on this deployment");
        }

        Tenant tenant = tenantRepository.findBySlug(slug)
                .orElseThrow(() -> new EntityNotFoundException("Tenant not found: " + slug));

        // Extract RFC 7591 fields from the request body
        @SuppressWarnings("unchecked")
        List<String> redirectUris = registrationRequest.get("redirect_uris") instanceof List<?> list
                ? list.stream().map(Object::toString).toList()
                : List.of();

        String clientName = registrationRequest.get("client_name") instanceof String s ? s : null;

        @SuppressWarnings("unchecked")
        List<String> grantTypes = registrationRequest.get("grant_types") instanceof List<?> list
                ? list.stream().map(Object::toString).toList()
                : List.of("authorization_code");

        String scope = registrationRequest.get("scope") instanceof String s ? s : "openid";
        List<String> scopes = List.of(scope.split("\\s+"));

        String tokenEndpointAuthMethod = registrationRequest.get("token_endpoint_auth_method") instanceof String s
                ? s : "client_secret_basic";

        // Build the DTO for the service layer. Passing token_endpoint_auth_method
        // through lets the service classify the client: 'none' becomes a public
        // PKCE-only client (no secret), anything else a confidential client.
        // RFC 7591 has no web_origins, but a public client with a browser
        // redirect is refused without one (PR #126) -- correctly, since it
        // could not sign anyone in. Derive it from the redirect URIs rather
        // than refuse a spec-conformant request that has no way to express it.
        List<String> webOrigins = stringList(registrationRequest.get("web_origins"));
        if (webOrigins.isEmpty()) {
            webOrigins = browserOriginsOf(redirectUris);
        }

        OidcClientDto dto = OidcClientDto.builder()
                .name(clientName)
                .redirectUris(redirectUris)
                .grantTypes(grantTypes)
                .scopes(scopes)
                .webOrigins(webOrigins)
                .tokenEndpointAuthMethod(tokenEndpointAuthMethod)
                .build();

        // Delegate to the existing create method (sets tenant context via slug)
        // We need to use the service directly, which requires tenant context.
        // The OidcClientService uses TenantAccessor, so the tenant resolver
        // filter should have already set the slug context from the URL.
        // Not create(): that requires a tenant admin, which is why this
        // endpoint answered 403 to every caller it exists for.
        OidcClientDto created = oidcClientService.createForDynamicRegistration(dto);

        // Build RFC 7591 response
        String baseUrl = baseUrl(request);
        String registrationClientUri = baseUrl + "/t/" + slug + "/oauth2/register/" + created.getClientId();

        // CONF-4.3 / RFC 7592: the credential that authorises this client to
        // manage its own registration through registration_client_uri. Shown
        // once, here; only its hash is stored.
        String registrationAccessToken = oidcClientService.issueRegistrationAccessToken(
                tenant.getId(), created.getClientId());

        Map<String, Object> response = new LinkedHashMap<>();
        response.put("client_id", created.getClientId());
        response.put("client_secret", created.getClientSecret());
        response.put("registration_access_token", registrationAccessToken);
        response.put("client_id_issued_at", Instant.now().getEpochSecond());
        response.put("client_secret_expires_at", 0); // does not expire
        response.put("registration_client_uri", registrationClientUri);
        response.put("redirect_uris", created.getRedirectUris());
        response.put("grant_types", created.getGrantTypes());
        response.put("scope", String.join(" ", created.getScopes()));
        // Echo the method the service actually settled on, not the request's.
        response.put("token_endpoint_auth_method", created.getTokenEndpointAuthMethod());
        if (clientName != null) {
            response.put("client_name", clientName);
        }

        log.info("Dynamic client registration for tenant {} — clientId={}",
                slug, created.getClientId());

        auditService.recordAnonymous(AuditEventTypes.OIDC_CLIENT_DYNAMIC_REGISTER,
                tech.cwvermaak.weldforge.model.AuditEvent.Outcome.SUCCESS,
                tenant.getId(), null,
                AuditEventTypes.TARGET_OIDC_CLIENT, created.getClientId(),
                AuditService.meta("client_name", clientName, "tenant_slug", slug));

        return ResponseEntity.status(201).body(response);
    }

    @ExceptionHandler(EntityNotFoundException.class)
    public ResponseEntity<Map<String, String>> handleNotFound(EntityNotFoundException e) {
        return ResponseEntity.status(404).body(Map.of("error", e.getMessage()));
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<Map<String, String>> handleBadRequest(IllegalArgumentException e) {
        return ResponseEntity.status(400).body(Map.of(
                "error", "invalid_client_metadata",
                "error_description", e.getMessage()));
    }

    private static String baseUrl(HttpServletRequest request) {
        String scheme = request.getScheme();
        String host = request.getServerName();
        int port = request.getServerPort();
        String forwarded = request.getHeader("X-Forwarded-Proto");
        if (forwarded != null) scheme = forwarded;
        if (("http".equals(scheme) && port == 80) || ("https".equals(scheme) && port == 443)) {
            return scheme + "://" + host;
        }
        return scheme + "://" + host + ":" + port;
    }

    // ---- RFC 7592 client configuration endpoint (CONF-4.3) ------------

    /**
     * Read this client's own registration.
     *
     * <p>Authorised by the registration access token as a bearer credential,
     * which is the only thing that can authorise it: the client secret is not
     * usable here because a public client has none, and admin credentials would
     * make this a different endpoint on a different surface.
     */
    @GetMapping(value = "/t/{slug}/oauth2/register/{clientId}",
                produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Map<String, Object>> read(@PathVariable String slug,
                                                    @PathVariable String clientId,
                                                    HttpServletRequest request) {
        Tenant tenant = tenantRepository.findBySlug(slug)
                .orElseThrow(() -> new EntityNotFoundException("Tenant not found: " + slug));
        OidcClient client = authorise(tenant, clientId, request);
        return ResponseEntity.ok(metadata(client, slug, request));
    }

    /**
     * Update this client's own registration (RFC 7592 §2.2).
     *
     * <p>The registration response has advertised a
     * {@code registration_client_uri} since it was written, and GET and DELETE
     * answered on it — but there was no PUT, so the management URI we handed
     * every dynamically registered client could read and destroy its
     * registration and not change it. A client that needed one more redirect
     * URI had to delete itself and register again, which mints a new
     * {@code client_id} and breaks every token already issued to it.
     *
     * <p>RFC 7592 §2.2 is a REPLACE, not a merge: the request carries the
     * client's full intended metadata, and omitted fields are to be treated
     * as removed. That is the opposite of the admin PUT, which leaves nulls
     * alone — so this does NOT simply delegate to it. A client sending only
     * the field it wants changed would, under merge semantics, keep settings
     * it believes it has dropped.
     *
     * <p>{@code client_id} must be present and must match the URI, per §2.2.
     * {@code client_secret} may be echoed back but is never changed here;
     * rotation is a separate, deliberate act.
     */
    @PutMapping(value = "/t/{slug}/oauth2/register/{clientId}",
                consumes = MediaType.APPLICATION_JSON_VALUE,
                produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Map<String, Object>> update(@PathVariable String slug,
                                                      @PathVariable String clientId,
                                                      @RequestBody Map<String, Object> body,
                                                      HttpServletRequest request) {
        Tenant tenant = tenantRepository.findBySlug(slug)
                .orElseThrow(() -> new EntityNotFoundException("Tenant not found: " + slug));
        OidcClient client = authorise(tenant, clientId, request);

        // §2.2: the body MUST include client_id, and it MUST match the one
        // being managed. Without this a client holding one registration token
        // could post another client's id and be answered about that client.
        Object bodyClientId = body == null ? null : body.get("client_id");
        if (bodyClientId == null || !clientId.equals(bodyClientId.toString())) {
            throw new IllegalArgumentException(
                    "client_id is required and must match the registration being updated");
        }

        // A client may not promote itself. token_endpoint_auth_method decides
        // public vs confidential, and switching it would either hand a public
        // client a secret it cannot keep or strip authentication from a
        // confidential one -- neither is this endpoint's to do.
        Object method = body.get("token_endpoint_auth_method");
        if (method != null && !method.toString().equals(client.getTokenEndpointAuthMethod())) {
            throw new IllegalArgumentException(
                    "token_endpoint_auth_method cannot be changed; register a new client instead");
        }

        List<String> redirectUris = stringList(body.get("redirect_uris"));
        if (redirectUris.isEmpty()) {
            throw new IllegalArgumentException("redirect_uris must be present and non-empty");
        }

        // REPLACE semantics: everything the client did not send is cleared,
        // which is what §2.2 requires and why each list is read unconditionally
        // rather than only when present.
        OidcClientDto patch = OidcClientDto.builder()
                .name(body.get("client_name") instanceof String s ? s : null)
                .redirectUris(redirectUris)
                .scopes(body.get("scope") instanceof String s && !s.isBlank()
                        ? List.of(s.trim().split("\s+")) : List.of("openid"))
                .grantTypes(stringList(body.get("grant_types")).isEmpty()
                        ? List.of("authorization_code") : stringList(body.get("grant_types")))
                .postLogoutRedirectUris(stringList(body.get("post_logout_redirect_uris")))
                .webOrigins(stringList(body.get("web_origins")))
                .build();

        // updateById, not update: the registration access token already proved
        // the caller may manage this client, and there is no admin session here.
        oidcClientService.updateById(client.getId(), patch);

        auditService.recordAnonymous(AuditEventTypes.OIDC_CLIENT_DYNAMIC_UPDATE,
                tech.cwvermaak.weldforge.model.AuditEvent.Outcome.SUCCESS,
                tenant.getId(), null,
                AuditEventTypes.TARGET_OIDC_CLIENT, clientId,
                AuditService.meta("tenant_slug", slug));

        OidcClient refreshed = authorise(tenant, clientId, request);
        return ResponseEntity.ok(metadata(refreshed, slug, request));
    }

    /**
     * The origins implied by redirect URIs that run in a browser.
     *
     * <p>Mirrors the portal's rule and the server's guard: only a real
     * http(s) host implies a browser. RFC 8252 loopback and private-use
     * schemes correctly contribute nothing.
     */
    private static List<String> browserOriginsOf(List<String> redirectUris) {
        java.util.LinkedHashSet<String> origins = new java.util.LinkedHashSet<>();
        for (String raw : redirectUris) {
            try {
                java.net.URI uri = java.net.URI.create(raw.trim());
                String scheme = uri.getScheme();
                String host = uri.getHost();
                if (scheme == null || host == null) continue;
                if (!"http".equalsIgnoreCase(scheme) && !"https".equalsIgnoreCase(scheme)) continue;
                if (host.equalsIgnoreCase("localhost") || "127.0.0.1".equals(host)
                        || "[::1]".equals(host) || "::1".equals(host)) continue;
                origins.add(uri.getPort() < 0
                        ? scheme + "://" + host
                        : scheme + "://" + host + ":" + uri.getPort());
            } catch (IllegalArgumentException ignored) {
                // Not a URI we understand; the service validates separately.
            }
        }
        return List.copyOf(origins);
    }

    /** Read a JSON array of strings; anything else yields an empty list. */
    private static List<String> stringList(Object raw) {
        return raw instanceof List<?> list
                ? list.stream().filter(java.util.Objects::nonNull).map(Object::toString).toList()
                : List.of();
    }

    /**
     * Delete this client's own registration (RFC 7592 §2.3).
     *
     * <p>204 with no body on success. This is the operation a client calls when
     * it is being decommissioned, and it is why the token is worth hashing: it
     * can destroy a working integration.
     */
    @DeleteMapping("/t/{slug}/oauth2/register/{clientId}")
    public ResponseEntity<Void> delete(@PathVariable String slug,
                                       @PathVariable String clientId,
                                       HttpServletRequest request) {
        Tenant tenant = tenantRepository.findBySlug(slug)
                .orElseThrow(() -> new EntityNotFoundException("Tenant not found: " + slug));
        OidcClient client = authorise(tenant, clientId, request);

        oidcClientService.deleteById(client.getId());

        auditService.recordAnonymous(AuditEventTypes.OIDC_CLIENT_DYNAMIC_DELETE,
                tech.cwvermaak.weldforge.model.AuditEvent.Outcome.SUCCESS,
                tenant.getId(), null,
                AuditEventTypes.TARGET_OIDC_CLIENT, clientId,
                AuditService.meta("tenant_slug", slug));

        return ResponseEntity.noContent().build();
    }

    /**
     * Resolve the client this request is authorised to manage, or fail.
     *
     * <p>Every failure is a 403 carrying no detail, and deliberately the same
     * 403: a distinct 404 for "no such client" would turn this endpoint into a
     * way to enumerate which client ids exist on a tenant, which is precisely
     * what an open registration endpoint should not hand out.
     *
     * <p>A client with no stored token hash is <em>not self-manageable</em> —
     * it was created through the admin API and is managed there. That is a
     * refusal, not a prompt to mint a token on demand.
     */
    private OidcClient authorise(Tenant tenant, String clientId, HttpServletRequest request) {
        String header = request.getHeader("Authorization");
        if (header == null || !header.startsWith("Bearer ")) {
            throw new RegistrationForbiddenException();
        }
        String presented = header.substring(7).trim();

        OidcClient client = oidcClientRepository
                .findByTenantIdAndClientId(tenant.getId(), clientId)
                .orElseThrow(RegistrationForbiddenException::new);

        String stored = client.getRegistrationAccessTokenHash();
        if (stored == null || stored.isBlank()) {
            throw new RegistrationForbiddenException();
        }
        if (!java.security.MessageDigest.isEqual(
                stored.getBytes(java.nio.charset.StandardCharsets.UTF_8),
                OidcClientService.hashRegistrationToken(presented)
                        .getBytes(java.nio.charset.StandardCharsets.UTF_8))) {
            throw new RegistrationForbiddenException();
        }
        return client;
    }

    /** The RFC 7591 client metadata document, minus anything secret. */
    private Map<String, Object> metadata(OidcClient client, String slug, HttpServletRequest request) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("client_id", client.getClientId());
        body.put("registration_client_uri",
                baseUrl(request) + "/t/" + slug + "/oauth2/register/" + client.getClientId());
        body.put("redirect_uris", client.getRedirectUriList());
        body.put("grant_types", client.getGrantTypeList());
        body.put("scope", String.join(" ", client.getScopeList()));
        body.put("token_endpoint_auth_method", client.getTokenEndpointAuthMethod());
        if (client.getName() != null) body.put("client_name", client.getName());
        // Neither the client secret nor the registration access token is
        // reissued here. Both were shown once at registration; re-serving them
        // would make a leaked token enough to recover the secret too.
        return body;
    }

    /** Marker for the single, uniform 403 the management endpoints return. */
    private static class RegistrationForbiddenException extends RuntimeException {
        RegistrationForbiddenException() {
            super("Not authorised to manage this client registration");
        }
    }

    @ExceptionHandler(RegistrationForbiddenException.class)
    public ResponseEntity<Map<String, String>> handleForbidden(RegistrationForbiddenException e) {
        return ResponseEntity.status(403).body(Map.of("error", "invalid_token"));
    }
}
