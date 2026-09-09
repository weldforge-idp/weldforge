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
        OidcClientDto dto = OidcClientDto.builder()
                .name(clientName)
                .redirectUris(redirectUris)
                .grantTypes(grantTypes)
                .scopes(scopes)
                .tokenEndpointAuthMethod(tokenEndpointAuthMethod)
                .build();

        // Delegate to the existing create method (sets tenant context via slug)
        // We need to use the service directly, which requires tenant context.
        // The OidcClientService uses TenantAccessor, so the tenant resolver
        // filter should have already set the slug context from the URL.
        OidcClientDto created = oidcClientService.create(dto);

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
