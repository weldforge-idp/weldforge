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
                .tokenEndpointAuthMethod(isPublic ? "none" : "client_secret_post")
                .build();
        OidcClient saved = repository.save(client);

        OidcClientDto out = toDto(saved, true);
        // A public client has no usable secret — never hand one back.
        out.setClientSecret(isPublic ? null : clientSecret); // confidential: shown once
        return out;
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
}
