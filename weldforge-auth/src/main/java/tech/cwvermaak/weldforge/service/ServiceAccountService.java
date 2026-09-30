package tech.cwvermaak.weldforge.service;

import jakarta.persistence.EntityNotFoundException;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import tech.cwvermaak.weldforge.config.tenant.TenantAccessor;
import tech.cwvermaak.weldforge.model.AdminRole;
import tech.cwvermaak.weldforge.model.ServiceAccount;
import tech.cwvermaak.weldforge.model.Tenant;
import tech.cwvermaak.weldforge.model.dto.ServiceAccountDto;
import tech.cwvermaak.weldforge.repository.ServiceAccountRepository;
import tech.cwvermaak.weldforge.service.audit.AuditEventTypes;
import tech.cwvermaak.weldforge.service.audit.AuditService;
import tech.cwvermaak.weldforge.service.security.ApiKeyHasher;

import java.time.LocalDateTime;
import java.security.SecureRandom;
import java.util.HexFormat;
import java.util.List;

/**
 * CRUD for service accounts (PRD TOK-03). Tenant-isolated via
 * {@link TenantAccessor}; a TENANT_ADMIN can only manage accounts inside
 * their own tenant. Only SUPER_ADMIN may grant SUPER_ADMIN to a service
 * account, mirroring the user-side rule in {@link AdminService#setAdminRole}.
 */
@Service
@RequiredArgsConstructor
public class ServiceAccountService {

    private static final SecureRandom RNG = new SecureRandom();

    private final TenantAccessor tenantAccessor;
    private final ServiceAccountRepository repository;
    private final AuditService auditService;

    @Transactional(readOnly = true)
    public List<ServiceAccountDto> list() {
        tenantAccessor.requireAnyAdmin();
        Long tid = tenantAccessor.requireTenantId();
        return repository.findByTenantId(tid).stream()
                .map(ServiceAccountService::toMaskedDto)
                .toList();
    }

    @Transactional
    public ServiceAccountDto create(ServiceAccountDto dto) {
        tenantAccessor.requireTenantAdmin();
        if (dto.getName() == null || dto.getName().isBlank()) {
            throw new IllegalArgumentException("Service account name is required");
        }
        AdminRole role = dto.getAdminRole() == null ? AdminRole.NONE : dto.getAdminRole();
        if (role == AdminRole.SUPER_ADMIN && !tenantAccessor.isSuperAdmin()) {
            throw new org.springframework.security.access.AccessDeniedException(
                    "Only a super admin may grant SUPER_ADMIN to a service account");
        }
        Tenant tenant = tenantAccessor.requireTenant();
        String raw = generateToken();

        // Duration wins when supplied; a caller written before these fields
        // existed still passes an absolute expiresAt and is unaffected.
        var expiry = ServiceAccountExpiry.resolve(
                dto.getExpiresInDays(), dto.getExpiresInHours(), LocalDateTime.now());
        LocalDateTime expiresAt = expiry.applyTo(dto.getExpiresAt());

        ServiceAccount sa = ServiceAccount.builder()
                .tenant(tenant)
                .name(dto.getName().trim())
                .description(dto.getDescription())
                .tokenPrefix(ApiKeyHasher.displayPrefix(raw))
                .tokenHash(ApiKeyHasher.hash(raw))
                .adminRole(role)
                .enabled(dto.getEnabled() == null || dto.getEnabled())
                .expiresAt(expiresAt)
                .build();
        ServiceAccount saved = repository.save(sa);

        auditService.recordAdmin(AuditEventTypes.SERVICE_ACCOUNT_CREATE, null,
                AuditEventTypes.TARGET_SERVICE_ACCOUNT, String.valueOf(saved.getId()),
                AuditService.meta(
                        "name", saved.getName(),
                        "admin_role", role.name(),
                        "prefix", saved.getTokenPrefix(),
                        // A permanent credential is a standing risk, so the
                        // audit trail should say plainly that one was issued.
                        "expires_at", saved.getExpiresAt() == null
                                ? "indefinite" : saved.getExpiresAt().toString()));

        ServiceAccountDto out = toMaskedDto(saved);
        out.setToken(raw); // single-reveal
        return out;
    }

    @Transactional
    public ServiceAccountDto rotate(Long id) {
        return rotate(id, null);
    }

    /**
     * Issue a new secret for an existing service account, optionally setting
     * a new lifetime.
     *
     * @param request may carry {@code expiresInDays} / {@code expiresInHours};
     *                null or absent leaves the existing expiry alone
     */
    @Transactional
    public ServiceAccountDto rotate(Long id, ServiceAccountDto request) {
        tenantAccessor.requireTenantAdmin();
        ServiceAccount sa = loadOwn(id);
        LocalDateTime now = LocalDateTime.now();

        var expiry = request == null
                ? new ServiceAccountExpiry.Resolved(ServiceAccountExpiry.Intent.UNCHANGED, null)
                : ServiceAccountExpiry.resolve(
                        request.getExpiresInDays(), request.getExpiresInHours(), now);

        // Rotating an already-expired account without giving it a new lifetime
        // hands back a credential that cannot authenticate. The old behaviour
        // did exactly that, silently, and the caller had no way to tell a dead
        // token from a live one until the first 401.
        boolean alreadyExpired = sa.getExpiresAt() != null && sa.getExpiresAt().isBefore(now);
        if (alreadyExpired && expiry.intent() == ServiceAccountExpiry.Intent.UNCHANGED) {
            throw new IllegalArgumentException(
                    "This token expired on " + sa.getExpiresAt() + ". Rotating it would issue "
                    + "another expired token — set a new lifetime (expiresInDays, or 0 to never "
                    + "expire) when rotating.");
        }

        String raw = generateToken();
        sa.setTokenPrefix(ApiKeyHasher.displayPrefix(raw));
        sa.setTokenHash(ApiKeyHasher.hash(raw));
        sa.setExpiresAt(expiry.applyTo(sa.getExpiresAt()));

        auditService.recordAdmin(AuditEventTypes.SERVICE_ACCOUNT_ROTATE, null,
                AuditEventTypes.TARGET_SERVICE_ACCOUNT, String.valueOf(sa.getId()),
                AuditService.meta("prefix", sa.getTokenPrefix(),
                        "expires_at", sa.getExpiresAt() == null
                                ? "indefinite" : sa.getExpiresAt().toString()));

        ServiceAccountDto out = toMaskedDto(sa);
        out.setToken(raw);
        return out;
    }

    @Transactional
    public ServiceAccountDto update(Long id, ServiceAccountDto dto) {
        tenantAccessor.requireTenantAdmin();
        ServiceAccount sa = loadOwn(id);
        if (dto.getDescription() != null) sa.setDescription(dto.getDescription());
        if (dto.getEnabled() != null) sa.setEnabled(dto.getEnabled());
        // Duration first, so `expiresInDays: 0` can make a token permanent
        // again. Before this there was no way back: a bare null read as
        // "leave alone", so an expiry once set could only ever be moved.
        var expiry = ServiceAccountExpiry.resolve(
                dto.getExpiresInDays(), dto.getExpiresInHours(), LocalDateTime.now());
        if (expiry.intent() != ServiceAccountExpiry.Intent.UNCHANGED) {
            sa.setExpiresAt(expiry.applyTo(sa.getExpiresAt()));
        } else if (dto.getExpiresAt() != null) {
            sa.setExpiresAt(dto.getExpiresAt());
        }
        if (dto.getAdminRole() != null) {
            if (dto.getAdminRole() == AdminRole.SUPER_ADMIN && !tenantAccessor.isSuperAdmin()) {
                throw new org.springframework.security.access.AccessDeniedException(
                        "Only a super admin may grant SUPER_ADMIN to a service account");
            }
            sa.setAdminRole(dto.getAdminRole());
        }
        return toMaskedDto(sa);
    }

    @Transactional
    public void delete(Long id) {
        tenantAccessor.requireTenantAdmin();
        ServiceAccount sa = loadOwn(id);
        repository.delete(sa);
        auditService.recordAdmin(AuditEventTypes.SERVICE_ACCOUNT_DELETE, null,
                AuditEventTypes.TARGET_SERVICE_ACCOUNT, String.valueOf(id),
                AuditService.meta("name", sa.getName()));
    }

    private ServiceAccount loadOwn(Long id) {
        Long tid = tenantAccessor.requireTenantId();
        return repository.findByIdAndTenantId(id, tid)
                .orElseThrow(() -> new EntityNotFoundException("Service account " + id + " not found"));
    }

    private static ServiceAccountDto toMaskedDto(ServiceAccount sa) {
        Tenant t = sa.getTenant();
        return ServiceAccountDto.builder()
                .id(sa.getId())
                .name(sa.getName())
                .description(sa.getDescription())
                .tenantSlug(t != null ? t.getSlug() : null)
                .tenantName(t == null ? null
                        : (t.getDisplayName() != null && !t.getDisplayName().isBlank()
                            ? t.getDisplayName() : t.getName()))
                .tokenPrefix(sa.getTokenPrefix())
                .adminRole(sa.getAdminRole())
                .enabled(sa.isEnabled())
                .expiresAt(sa.getExpiresAt())
                .createdAt(sa.getCreatedAt())
                .lastUsedAt(sa.getLastUsedAt())
                .build();
    }

    private static String generateToken() {
        byte[] buf = new byte[24];
        RNG.nextBytes(buf);
        return ApiKeyHasher.SERVICE_ACCOUNT_PREFIX + HexFormat.of().formatHex(buf);
    }
}
