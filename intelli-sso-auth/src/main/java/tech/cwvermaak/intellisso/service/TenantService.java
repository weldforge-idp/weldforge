package tech.cwvermaak.intellisso.service;

import jakarta.persistence.EntityNotFoundException;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import tech.cwvermaak.intellisso.config.tenant.TenantAccessor;
import tech.cwvermaak.intellisso.model.SocialProviderType;
import tech.cwvermaak.intellisso.model.Tenant;
import tech.cwvermaak.intellisso.model.TenantSocialProvider;
import tech.cwvermaak.intellisso.model.User;
import tech.cwvermaak.intellisso.model.dto.SocialProviderDto;
import tech.cwvermaak.intellisso.model.dto.TenantDto;
import tech.cwvermaak.intellisso.repository.TenantRepository;
import tech.cwvermaak.intellisso.repository.TenantSocialProviderRepository;
import tech.cwvermaak.intellisso.repository.UserRepository;
import tech.cwvermaak.intellisso.service.audit.AuditEventTypes;
import tech.cwvermaak.intellisso.service.audit.AuditService;

import java.util.List;
import java.util.regex.Pattern;

/**
 * Tenant management with strict isolation:
 *
 * <ul>
 *   <li>A super admin sees and can manage every tenant (this is the only way
 *       to bring new tenants into existence).</li>
 *   <li>A regular tenant admin can only see, update, and configure social
 *       providers on <em>their own</em> tenant. Every other tenant is
 *       invisible to them — listing returns just their own row, looking up
 *       another tenant by id throws 403.</li>
 *   <li>No caller, super admin or otherwise, can mutate another tenant's
 *       social-provider config through a regular-admin session: the
 *       tenant id in the URL is always cross-checked against
 *       {@link TenantAccessor#requireSameTenant(Long)}.</li>
 * </ul>
 */
@Service
@RequiredArgsConstructor
public class TenantService {

    private static final Pattern SLUG_FORMAT =
            Pattern.compile("^[a-z0-9][a-z0-9-]{0,62}[a-z0-9]$");

    private final TenantAccessor tenantAccessor;
    private final TenantRepository tenantRepository;
    private final TenantSocialProviderRepository providerRepository;
    private final UserRepository userRepository;
    private final AuditService auditService;

    // ---- Tenant CRUD --------------------------------------------------

    public List<TenantDto> listTenants() {
        if (tenantAccessor.isSuperAdmin()) {
            return tenantRepository.findAll().stream().map(TenantService::toDto).toList();
        }
        // Regular caller: only ever sees their own tenant.
        return List.of(toDto(tenantAccessor.requireTenant()));
    }

    public TenantDto getTenant(Long id) {
        Tenant t = tenantRepository.findById(id)
                .orElseThrow(() -> new EntityNotFoundException("Tenant " + id + " not found"));
        tenantAccessor.requireSameTenant(t.getId());
        return toDto(t);
    }

    @Transactional
    public TenantDto createTenant(TenantDto dto) {
        // New tenants can only be minted by a super admin — otherwise a
        // regular admin could spin up a tenant and trivially see everyone
        // else's data via that tenant's APIs.
        tenantAccessor.requireSuperAdmin();

        String slug = requireSlug(dto.getSlug());
        if (tenantRepository.existsBySlug(slug)) {
            throw new IllegalArgumentException("Tenant slug already in use: " + slug);
        }
        Tenant t = Tenant.builder()
                .slug(slug)
                .name(dto.getName() != null ? dto.getName() : slug)
                .displayName(dto.getDisplayName())
                .enabled(dto.getEnabled() == null ? true : dto.getEnabled())
                .build();
        Tenant saved = tenantRepository.save(t);
        auditService.recordAdmin(AuditEventTypes.TENANT_CREATE, currentActor(),
                AuditEventTypes.TARGET_TENANT, String.valueOf(saved.getId()),
                AuditService.meta("slug", saved.getSlug(), "name", saved.getName()));
        return toDto(saved);
    }

    @Transactional
    public TenantDto updateTenant(Long id, TenantDto dto) {
        Tenant t = tenantRepository.findById(id)
                .orElseThrow(() -> new EntityNotFoundException("Tenant " + id + " not found"));
        tenantAccessor.requireSameTenant(t.getId());

        if (dto.getName() != null) t.setName(dto.getName());
        if (dto.getDisplayName() != null) t.setDisplayName(dto.getDisplayName());
        // Only a super admin may enable/disable a tenant.
        if (dto.getEnabled() != null) {
            if (!tenantAccessor.isSuperAdmin() && !dto.getEnabled().equals(t.getEnabled())) {
                throw new AccessDeniedException("Only a super admin can toggle tenant enable state");
            }
            t.setEnabled(dto.getEnabled());
        }
        // slug is immutable — changing it would break OAuth2 registration IDs.
        auditService.recordAdmin(AuditEventTypes.TENANT_UPDATE, currentActor(),
                AuditEventTypes.TARGET_TENANT, String.valueOf(t.getId()),
                AuditService.meta("slug", t.getSlug()));
        return toDto(t);
    }

    @Transactional
    public void deleteTenant(Long id) {
        // Hard-destructive: super admin only.
        tenantAccessor.requireSuperAdmin();
        Tenant t = tenantRepository.findById(id)
                .orElseThrow(() -> new EntityNotFoundException("Tenant " + id + " not found"));
        tenantRepository.delete(t);
        auditService.recordAdmin(AuditEventTypes.TENANT_DELETE, currentActor(),
                AuditEventTypes.TARGET_TENANT, String.valueOf(id),
                AuditService.meta("slug", t.getSlug()));
    }

    // ---- Social provider CRUD ----------------------------------------

    public List<SocialProviderDto> listProviders(Long tenantId) {
        Tenant t = tenantRepository.findById(tenantId)
                .orElseThrow(() -> new EntityNotFoundException("Tenant " + tenantId + " not found"));
        tenantAccessor.requireSameTenant(t.getId());
        return providerRepository.findByTenantId(tenantId).stream()
                .map(p -> toDto(p, t.getSlug()))
                .toList();
    }

    @Transactional
    public SocialProviderDto upsertProvider(Long tenantId, SocialProviderDto dto) {
        if (dto.getProvider() == null) {
            throw new IllegalArgumentException("provider is required");
        }
        if (dto.getClientId() == null || dto.getClientId().isBlank()) {
            throw new IllegalArgumentException("clientId is required");
        }
        Tenant tenant = tenantRepository.findById(tenantId)
                .orElseThrow(() -> new EntityNotFoundException("Tenant " + tenantId + " not found"));
        tenantAccessor.requireSameTenant(tenant.getId());

        TenantSocialProvider existing = providerRepository
                .findByTenantIdAndProvider(tenantId, dto.getProvider())
                .orElse(null);

        if (existing == null) {
            if (dto.getClientSecret() == null || dto.getClientSecret().isBlank()) {
                throw new IllegalArgumentException("clientSecret is required for a new provider");
            }
            TenantSocialProvider fresh = TenantSocialProvider.builder()
                    .tenant(tenant)
                    .provider(dto.getProvider())
                    .displayName(dto.getDisplayName())
                    .clientId(dto.getClientId())
                    .clientSecret(dto.getClientSecret())
                    .scopes(dto.getScopes())
                    .enabled(dto.getEnabled() == null ? true : dto.getEnabled())
                    .build();
            TenantSocialProvider saved = providerRepository.save(fresh);
            auditService.recordAdmin(AuditEventTypes.SOCIAL_PROVIDER_UPSERT, currentActor(),
                    AuditEventTypes.TARGET_SOCIAL_PROVIDER, String.valueOf(saved.getId()),
                    AuditService.meta("tenant", tenant.getSlug(), "provider", saved.getProvider().name(), "created", true));
            return toDto(saved, tenant.getSlug());
        }

        existing.setClientId(dto.getClientId());
        if (dto.getClientSecret() != null && !dto.getClientSecret().isBlank()) {
            existing.setClientSecret(dto.getClientSecret());
        }
        if (dto.getDisplayName() != null) existing.setDisplayName(dto.getDisplayName());
        if (dto.getScopes() != null) existing.setScopes(dto.getScopes());
        if (dto.getEnabled() != null) existing.setEnabled(dto.getEnabled());
        auditService.recordAdmin(AuditEventTypes.SOCIAL_PROVIDER_UPSERT, currentActor(),
                AuditEventTypes.TARGET_SOCIAL_PROVIDER, String.valueOf(existing.getId()),
                AuditService.meta("tenant", tenant.getSlug(), "provider", existing.getProvider().name(), "created", false));
        return toDto(existing, tenant.getSlug());
    }

    @Transactional
    public void deleteProvider(Long tenantId, SocialProviderType provider) {
        Tenant tenant = tenantRepository.findById(tenantId)
                .orElseThrow(() -> new EntityNotFoundException("Tenant " + tenantId + " not found"));
        tenantAccessor.requireSameTenant(tenant.getId());
        providerRepository.findByTenantIdAndProvider(tenantId, provider)
                .ifPresent(row -> {
                    providerRepository.delete(row);
                    auditService.recordAdmin(AuditEventTypes.SOCIAL_PROVIDER_DELETE, currentActor(),
                            AuditEventTypes.TARGET_SOCIAL_PROVIDER, String.valueOf(row.getId()),
                            AuditService.meta("tenant", tenant.getSlug(), "provider", provider.name()));
                });
    }

    private User currentActor() {
        String tenantSlug = tech.cwvermaak.intellisso.config.tenant.TenantContext.get();
        var auth = org.springframework.security.core.context.SecurityContextHolder.getContext().getAuthentication();
        if (tenantSlug == null || auth == null || !(auth.getPrincipal() instanceof String email)) return null;
        return userRepository.findByTenant_SlugAndEmailIgnoreCase(tenantSlug, email).orElse(null);
    }

    // ---- Public discovery --------------------------------------------

    /**
     * Enabled providers for a tenant — unauthenticated callers hit this to
     * discover which social login buttons to render. No secrets are returned.
     */
    public List<SocialProviderDto> listEnabledProvidersForSlug(String slug) {
        Tenant t = tenantRepository.findBySlug(slug)
                .orElseThrow(() -> new EntityNotFoundException("Tenant " + slug + " not found"));
        return providerRepository.findByTenantIdAndEnabledTrue(t.getId()).stream()
                .map(p -> {
                    SocialProviderDto d = toDto(p, t.getSlug());
                    d.setClientId(null);
                    d.setClientSecret(null);
                    return d;
                })
                .toList();
    }

    // ---- Mapping ------------------------------------------------------

    private static TenantDto toDto(Tenant t) {
        return TenantDto.builder()
                .id(t.getId())
                .slug(t.getSlug())
                .name(t.getName())
                .displayName(t.getDisplayName())
                .enabled(t.getEnabled())
                .build();
    }

    private static SocialProviderDto toDto(TenantSocialProvider p, String tenantSlug) {
        return SocialProviderDto.builder()
                .id(p.getId())
                .tenantId(p.getTenant().getId())
                .provider(p.getProvider())
                .displayName(p.getDisplayName())
                .clientId(p.getClientId())
                .scopes(p.getScopes())
                .enabled(p.getEnabled())
                .registrationId(tenantSlug + "-" + p.getProvider().name().toLowerCase())
                .build();
    }

    private static String requireSlug(String slug) {
        if (slug == null) throw new IllegalArgumentException("slug is required");
        String normalised = slug.trim().toLowerCase();
        if (!SLUG_FORMAT.matcher(normalised).matches()) {
            throw new IllegalArgumentException(
                "slug must be lowercase alphanumeric + dashes, 2-64 chars, not starting/ending with '-'");
        }
        return normalised;
    }
}
