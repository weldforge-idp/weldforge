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
import tech.cwvermaak.weldforge.repository.TenantRepository;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.List;
import java.util.UUID;

/**
 * Tenant-scoped admin operations for OIDC relying parties. Every method
 * takes the target {@code tenantId} explicitly (sourced from the URL by
 * {@link tech.cwvermaak.weldforge.controller.OidcAdminController}) so a
 * SUPER_ADMIN can manage another tenant's clients without first
 * impersonating that tenant. Tenant isolation is enforced by
 * {@link TenantAccessor#requireSameTenant(Long)} — non-super admins
 * targeting a foreign tenant are rejected with AccessDeniedException.
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
    private final TenantRepository tenantRepository;

    public List<OidcClientDto> list(Long tenantId) {
        tenantAccessor.requireAnyAdmin();
        tenantAccessor.requireSameTenant(tenantId);
        return repository.findByTenantId(tenantId).stream()
                .map(c -> toDto(c, false))
                .toList();
    }

    @Transactional
    public OidcClientDto create(Long tenantId, OidcClientDto dto) {
        tenantAccessor.requireTenantAdmin();
        tenantAccessor.requireSameTenant(tenantId);
        Tenant tenant = tenantRepository.findById(tenantId)
                .orElseThrow(() -> new EntityNotFoundException("Tenant " + tenantId + " not found"));
        require(dto.getRedirectUris(), "redirectUris");
        require(dto.getScopes(),       "scopes");
        require(dto.getGrantTypes(),   "grantTypes");

        String clientId = dto.getClientId() != null && !dto.getClientId().isBlank()
                ? dto.getClientId()
                : "wf_client_" + UUID.randomUUID().toString().replace("-", "");
        String clientSecret = generateSecret();

        if (repository.findByTenantIdAndClientId(tenant.getId(), clientId).isPresent()) {
            throw new IllegalArgumentException("clientId already in use for this tenant");
        }

        OidcClient client = OidcClient.builder()
                .tenant(tenant)
                .clientId(clientId)
                .clientSecret(clientSecret)
                .name(dto.getName())
                .redirectUris(String.join(" ", dto.getRedirectUris()))
                .scopes(String.join(" ", dto.getScopes()))
                .grantTypes(String.join(" ", dto.getGrantTypes()))
                .requirePkce(dto.getRequirePkce() == null ? true : dto.getRequirePkce())
                .requireMfa(Boolean.TRUE.equals(dto.getRequireMfa()))
                .maxAuthenticationAgeSeconds(dto.getMaxAuthenticationAgeSeconds() != null
                        ? dto.getMaxAuthenticationAgeSeconds() : 0)
                .build();
        OidcClient saved = repository.save(client);

        OidcClientDto out = toDto(saved, true);
        out.setClientSecret(clientSecret); // shown once
        return out;
    }

    @Transactional
    public OidcClientDto rotateSecret(Long tenantId, Long id) {
        tenantAccessor.requireTenantAdmin();
        tenantAccessor.requireSameTenant(tenantId);
        OidcClient client = repository.findByIdAndTenantId(id, tenantId)
                .orElseThrow(() -> new EntityNotFoundException("OIDC client " + id + " not found"));
        String newSecret = generateSecret();
        client.setClientSecret(newSecret);
        OidcClientDto out = toDto(client, true);
        out.setClientSecret(newSecret);
        return out;
    }

    @Transactional
    public void delete(Long tenantId, Long id) {
        tenantAccessor.requireTenantAdmin();
        tenantAccessor.requireSameTenant(tenantId);
        OidcClient client = repository.findByIdAndTenantId(id, tenantId)
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
                // clientSecret intentionally null unless caller overrides.
                .build();
    }

    private static String generateSecret() {
        byte[] buf = new byte[32];
        RNG.nextBytes(buf);
        return "wfs_" + Base64.getUrlEncoder().withoutPadding().encodeToString(buf);
    }

    private static void require(List<String> v, String field) {
        if (v == null || v.isEmpty()) throw new IllegalArgumentException(field + " is required");
    }
}
