package tech.cwvermaak.intellisso.controller;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import jakarta.persistence.EntityNotFoundException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import tech.cwvermaak.intellisso.model.OidcClient;
import tech.cwvermaak.intellisso.model.Tenant;
import tech.cwvermaak.intellisso.model.User;
import tech.cwvermaak.intellisso.repository.OidcClientRepository;
import tech.cwvermaak.intellisso.repository.TenantRepository;
import tech.cwvermaak.intellisso.repository.UserRepository;
import tech.cwvermaak.intellisso.service.AuthService;
import tech.cwvermaak.intellisso.service.audit.AuditEventTypes;
import tech.cwvermaak.intellisso.service.audit.AuditService;
import tech.cwvermaak.intellisso.service.oidc.TenantSigningKeyService;

import java.net.URI;
import java.util.Optional;

/**
 * OIDC RP-initiated logout — PRD OID-04.
 *
 * Implements the relevant parts of the OpenID Connect RP-Initiated Logout
 * 1.0 spec:
 *
 * <ul>
 *   <li>Parses an optional {@code id_token_hint} JWT to identify the user.
 *   <li>Validates the {@code post_logout_redirect_uri} against the client's
 *       registered redirect URIs (we reuse the same list rather than
 *       maintaining a separate {@code post_logout_redirect_uris}).
 *   <li>Revokes the user's refresh tokens and bumps their token version,
 *       invalidating every outstanding access token on the next request.
 *   <li>Clears the session cookie.
 *   <li>Redirects (302) to {@code post_logout_redirect_uri} with the
 *       {@code state} parameter echoed back, or 204 if the caller did not
 *       supply a redirect URI.
 * </ul>
 */
@RestController
@RequiredArgsConstructor
@Slf4j
public class OidcLogoutController {

    public static final String SESSION_COOKIE =
            tech.cwvermaak.intellisso.config.JwtAuthenticationFilter.SESSION_COOKIE;
    public static final String REFRESH_COOKIE = AuthService.REFRESH_COOKIE;

    private final TenantRepository tenantRepository;
    private final UserRepository userRepository;
    private final OidcClientRepository oidcClientRepository;
    private final TenantSigningKeyService signingKeyService;
    private final AuthService authService;
    private final AuditService auditService;

    @GetMapping("/t/{slug}/oauth2/logout")
    public ResponseEntity<Void> logoutGet(@PathVariable String slug,
                                           @RequestParam(value = "id_token_hint", required = false) String idTokenHint,
                                           @RequestParam(value = "post_logout_redirect_uri", required = false) String postLogoutRedirectUri,
                                           @RequestParam(value = "client_id", required = false) String clientId,
                                           @RequestParam(value = "state", required = false) String state,
                                           HttpServletRequest request,
                                           HttpServletResponse response) {
        return handleLogout(slug, idTokenHint, postLogoutRedirectUri, clientId, state, request, response);
    }

    @PostMapping("/t/{slug}/oauth2/logout")
    public ResponseEntity<Void> logoutPost(@PathVariable String slug,
                                            @RequestParam(value = "id_token_hint", required = false) String idTokenHint,
                                            @RequestParam(value = "post_logout_redirect_uri", required = false) String postLogoutRedirectUri,
                                            @RequestParam(value = "client_id", required = false) String clientId,
                                            @RequestParam(value = "state", required = false) String state,
                                            HttpServletRequest request,
                                            HttpServletResponse response) {
        return handleLogout(slug, idTokenHint, postLogoutRedirectUri, clientId, state, request, response);
    }

    private ResponseEntity<Void> handleLogout(String slug, String idTokenHint, String postLogoutRedirectUri,
                                               String clientIdHint, String state,
                                               HttpServletRequest request, HttpServletResponse response) {
        Tenant tenant = tenantRepository.findBySlug(slug)
                .orElseThrow(() -> new EntityNotFoundException("Unknown tenant: " + slug));

        // Resolve the user, either from the id_token_hint or from the current session cookie.
        User user = resolveUserFromHint(tenant, idTokenHint).orElse(null);
        if (user == null) {
            user = resolveUserFromCookie(tenant, request).orElse(null);
        }

        // Resolve the client. Prefer the client_id from the id_token hint; fall back to query param.
        OidcClient client = null;
        if (idTokenHint != null && !idTokenHint.isBlank()) {
            client = resolveClientFromHint(tenant, idTokenHint).orElse(null);
        }
        if (client == null && clientIdHint != null && !clientIdHint.isBlank()) {
            client = oidcClientRepository.findByTenantIdAndClientId(tenant.getId(), clientIdHint).orElse(null);
        }

        // Validate post_logout_redirect_uri — it must be an exact match of one of the client's
        // registered redirect URIs. If no client resolved, we can't validate, so we refuse.
        String validatedRedirect = null;
        if (postLogoutRedirectUri != null && !postLogoutRedirectUri.isBlank()) {
            if (client == null) {
                log.warn("OIDC logout: post_logout_redirect_uri supplied without a resolvable client");
                return ResponseEntity.badRequest().build();
            }
            if (!client.getRedirectUriList().contains(postLogoutRedirectUri)) {
                log.warn("OIDC logout: post_logout_redirect_uri '{}' not in client's registered list",
                        postLogoutRedirectUri);
                return ResponseEntity.badRequest().build();
            }
            validatedRedirect = postLogoutRedirectUri;
        }

        // Revoke the user's sessions. Bumping token_version invalidates every
        // outstanding access token on the next JWT filter pass.
        if (user != null) {
            authService.logoutAll(user);
            auditService.recordUserAction(AuditEventTypes.AUTH_LOGOUT_RP_INITIATED,
                    user, AuditEventTypes.TARGET_USER, String.valueOf(user.getId()),
                    AuditService.meta(
                            "tenant", tenant.getSlug(),
                            "client_id", client != null ? client.getClientId() : null,
                            "has_redirect", validatedRedirect != null));
        }

        // Clear cookies so the browser doesn't re-present them on the next request.
        clearCookie(response, SESSION_COOKIE, "/");
        clearCookie(response, REFRESH_COOKIE, "/api/auth");

        if (validatedRedirect != null) {
            String location = validatedRedirect;
            if (state != null && !state.isBlank()) {
                location += (location.contains("?") ? "&" : "?")
                        + "state=" + java.net.URLEncoder.encode(state, java.nio.charset.StandardCharsets.UTF_8);
            }
            return ResponseEntity.status(302)
                    .location(URI.create(location))
                    .build();
        }
        return ResponseEntity.noContent().build();
    }

    // ---- Helpers ----------------------------------------------------

    private Optional<User> resolveUserFromHint(Tenant tenant, String idTokenHint) {
        if (idTokenHint == null || idTokenHint.isBlank()) return Optional.empty();
        try {
            Claims claims = parseTenantJwt(tenant, idTokenHint);
            String sub = claims.getSubject();
            if (sub == null) return Optional.empty();
            Long userId = Long.valueOf(sub);
            return userRepository.findByIdAndTenantId(userId, tenant.getId());
        } catch (Exception e) {
            log.debug("OIDC logout: could not resolve user from id_token_hint: {}", e.getMessage());
            return Optional.empty();
        }
    }

    private Optional<OidcClient> resolveClientFromHint(Tenant tenant, String idTokenHint) {
        try {
            Claims claims = parseTenantJwt(tenant, idTokenHint);
            String aud = claims.getAudience() != null && !claims.getAudience().isEmpty()
                    ? claims.getAudience().iterator().next() : null;
            if (aud == null) return Optional.empty();
            return oidcClientRepository.findByTenantIdAndClientId(tenant.getId(), aud);
        } catch (Exception e) {
            return Optional.empty();
        }
    }

    private Optional<User> resolveUserFromCookie(Tenant tenant, HttpServletRequest request) {
        if (request.getCookies() == null) return Optional.empty();
        for (Cookie c : request.getCookies()) {
            if (!SESSION_COOKIE.equals(c.getName())) continue;
            // The session cookie is a WeldForge JWT, not a tenant-signed one.
            // We don't parse it here — the logout endpoint accepts anonymous
            // calls too. A follow-up pass can wire in JwtService for this.
            return Optional.empty();
        }
        return Optional.empty();
    }

    private Claims parseTenantJwt(Tenant tenant, String jwt) throws JwtException {
        // Parse the tenant's ID token using the active signing key's public half.
        var activeKey = signingKeyService.getOrCreateActive(tenant);
        var publicKey = signingKeyService.loadPublicKey(activeKey);
        return io.jsonwebtoken.Jwts.parser()
                .verifyWith(publicKey)
                .build()
                .parseSignedClaims(jwt)
                .getPayload();
    }

    private static void clearCookie(HttpServletResponse response, String name, String path) {
        Cookie cookie = new Cookie(name, "");
        cookie.setPath(path);
        cookie.setHttpOnly(true);
        cookie.setSecure(true);
        cookie.setMaxAge(0);
        response.addCookie(cookie);
    }
}
