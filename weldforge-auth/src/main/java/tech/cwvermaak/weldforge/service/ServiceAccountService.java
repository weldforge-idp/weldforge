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

        ServiceAccount sa = ServiceAccount.builder()
                .tenant(tenant)
                .name(dto.getName().trim())
                .description(dto.getDescription())
                .tokenPrefix(ApiKeyHasher.displayPrefix(raw))
                .tokenHash(ApiKeyHasher.hash(raw))
                .adminRole(role)
                .enabled(dto.getEnabled() == null || dto.getEnabled())
                .expiresAt(dto.getExpiresAt())
                .build();
        ServiceAccount saved = repository.save(sa);

        auditService.recordAdmin(AuditEventTypes.SERVICE_ACCOUNT_CREATE, null,
                AuditEventTypes.TARGET_SERVICE_ACCOUNT, String.valueOf(saved.getId()),
                AuditService.meta(
                        "name", saved.getName(),
                        "admin_role", role.name(),
                        "prefix", saved.getTokenPrefix()));

        ServiceAccountDto out = toMaskedDto(saved);
        out.setToken(raw); // single-reveal
        return out;
    }

    @Transactional
    public ServiceAccountDto rotate(Long id) {
        tenantAccessor.requireTenantAdmin();
        ServiceAccount sa = loadOwn(id);
        String raw = generateToken();
        sa.setTokenPrefix(ApiKeyHasher.displayPrefix(raw));
        sa.setTokenHash(ApiKeyHasher.hash(raw));

        auditService.recordAdmin(AuditEventTypes.SERVICE_ACCOUNT_ROTATE, null,
                AuditEventTypes.TARGET_SERVICE_ACCOUNT, String.valueOf(sa.getId()),
                AuditService.meta("prefix", sa.getTokenPrefix()));

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
        if (dto.getExpiresAt() != null) sa.setExpiresAt(dto.getExpiresAt());
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
        return ServiceAccountDto.builder()
                .id(sa.getId())
                .name(sa.getName())
                .description(sa.getDescription())
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
