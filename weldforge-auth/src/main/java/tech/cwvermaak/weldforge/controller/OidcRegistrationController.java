package tech.cwvermaak.weldforge.controller;

import jakarta.persistence.EntityNotFoundException;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import tech.cwvermaak.weldforge.model.Tenant;
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
 * The endpoint is public (secured by rate limiting in production) because
 * the RFC design assumes open registration. A registration access token
 * for future management is not yet implemented.
 */
@RestController
@RequiredArgsConstructor
@Slf4j
public class OidcRegistrationController {

    private final OidcClientService oidcClientService;
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

        // Build the DTO for the service layer
        OidcClientDto dto = OidcClientDto.builder()
                .name(clientName)
                .redirectUris(redirectUris)
                .grantTypes(grantTypes)
                .scopes(scopes)
                .requirePkce("none".equals(tokenEndpointAuthMethod) ? true : null)
                .build();

        // The slug-resolved tenant is the registration target. Admin RBAC
        // is still enforced inside the service (requireTenantAdmin), so a
        // truly public RFC 7591 flow needs a separate code path; today this
        // only works when the caller is already authenticated as an admin
        // for the same tenant.
        OidcClientDto created = oidcClientService.create(tenant.getId(), dto);

        // Build RFC 7591 response
        String baseUrl = baseUrl(request);
        String registrationClientUri = baseUrl + "/t/" + slug + "/oauth2/register/" + created.getClientId();

        Map<String, Object> response = new LinkedHashMap<>();
        response.put("client_id", created.getClientId());
        response.put("client_secret", created.getClientSecret());
        response.put("client_id_issued_at", Instant.now().getEpochSecond());
        response.put("client_secret_expires_at", 0); // does not expire
        response.put("registration_client_uri", registrationClientUri);
        response.put("redirect_uris", created.getRedirectUris());
        response.put("grant_types", created.getGrantTypes());
        response.put("scope", String.join(" ", created.getScopes()));
        response.put("token_endpoint_auth_method", tokenEndpointAuthMethod);
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
}
