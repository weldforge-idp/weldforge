package tech.cwvermaak.intellisso.service;

import jakarta.persistence.EntityNotFoundException;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import tech.cwvermaak.intellisso.config.tenant.TenantAccessor;
import tech.cwvermaak.intellisso.model.*;
import tech.cwvermaak.intellisso.model.dto.*;
import tech.cwvermaak.intellisso.repository.*;
import tech.cwvermaak.intellisso.service.audit.AuditEventTypes;
import tech.cwvermaak.intellisso.service.audit.AuditService;
import tech.cwvermaak.intellisso.service.mfa.MfaService;

import java.security.SecureRandom;
import java.util.HexFormat;
import java.util.List;

/**
 * All admin operations run inside the caller's tenant. Every query method
 * loads the tenant id via {@link TenantAccessor} and filters by it, so it is
 * impossible to retrieve or mutate a row belonging to another tenant via
 * these endpoints.
 */
@Service
@RequiredArgsConstructor
public class AdminService {

    private final TenantAccessor tenantAccessor;
    private final RoleRepository roleRepository;
    private final UserRepository userRepository;
    private final EnvironmentRepository environmentRepository;
    private final AppClientRepository appClientRepository;
    private final MfaService mfaService;
    private final AuditService auditService;

    private static final SecureRandom RNG = new SecureRandom();

    // -------- Roles ---------------------------------------------------

    public List<RoleDto> listRoles() {
        Long tid = tenantAccessor.requireTenantId();
        return roleRepository.findByTenantId(tid).stream()
                .map(AdminService::toDto)
                .toList();
    }

    @Transactional
    public RoleDto createRole(RoleDto dto) {
        if (dto.getName() == null || dto.getName().trim().isEmpty()) {
            throw new IllegalArgumentException("Role name cannot be empty");
        }
        Tenant tenant = tenantAccessor.requireTenant();
        if (roleRepository.existsByTenantIdAndNameIgnoreCase(tenant.getId(), dto.getName().trim())) {
            throw new IllegalArgumentException("Role already exists in this tenant: " + dto.getName());
        }
        Role role = Role.builder()
                .tenant(tenant)
                .name(dto.getName().trim())
                .description(dto.getDescription())
                .build();
        return toDto(roleRepository.save(role));
    }

    @Transactional
    public RoleDto updateRole(Long id, RoleDto dto) {
        Long tid = tenantAccessor.requireTenantId();
        Role role = roleRepository.findByIdAndTenantId(id, tid)
                .orElseThrow(() -> new EntityNotFoundException("Role " + id + " not found"));
        if (dto.getName() != null && !dto.getName().isBlank()) role.setName(dto.getName().trim());
        if (dto.getDescription() != null) role.setDescription(dto.getDescription());
        return toDto(role);
    }

    @Transactional
    public void deleteRole(Long id) {
        Long tid = tenantAccessor.requireTenantId();
        Role role = roleRepository.findByIdAndTenantId(id, tid)
                .orElseThrow(() -> new EntityNotFoundException("Role " + id + " not found"));
        roleRepository.delete(role);
    }

    // -------- Users ---------------------------------------------------

    public List<UserResponseDto> listUsers() {
        tenantAccessor.requireAnyAdmin();
        Long tid = tenantAccessor.requireTenantId();
        return userRepository.findByTenantId(tid).stream()
                .map(AdminService::toDto)
                .toList();
    }

    public UserResponseDto getUser(Long id) {
        tenantAccessor.requireAnyAdmin();
        Long tid = tenantAccessor.requireTenantId();
        return toDto(userRepository.findByIdAndTenantId(id, tid)
                .orElseThrow(() -> new EntityNotFoundException("User " + id + " not found")));
    }

    @Transactional
    public void deleteUser(Long id) {
        tenantAccessor.requireTenantAdmin();
        Long tid = tenantAccessor.requireTenantId();
        User user = userRepository.findByIdAndTenantId(id, tid)
                .orElseThrow(() -> new EntityNotFoundException("User " + id + " not found"));
        if (user.isSuperAdmin() && !tenantAccessor.isSuperAdmin()) {
            throw new AccessDeniedException("Cannot delete a super admin");
        }
        userRepository.delete(user);
        User actor = currentActor();
        auditService.recordAdmin(AuditEventTypes.USER_DELETE, actor,
                AuditEventTypes.TARGET_USER, String.valueOf(id),
                AuditService.meta("deleted_email", user.getEmail()));
    }

    /**
     * Administrative MFA reset. Tenant-isolated: a tenant admin can only
     * reset users in their own tenant. Super admins can reset any user.
     * Always audit-logged — the caller gets back the number of factors
     * removed so the UI can confirm the action.
     */
    @Transactional
    public int resetUserMfa(Long targetUserId) {
        tenantAccessor.requireTenantAdmin();
        Long tid = tenantAccessor.requireTenantId();
        User target = userRepository.findByIdAndTenantId(targetUserId, tid)
                .orElseThrow(() -> new EntityNotFoundException("User " + targetUserId + " not found"));
        if (target.isSuperAdmin() && !tenantAccessor.isSuperAdmin()) {
            throw new AccessDeniedException("Cannot reset MFA for a super admin");
        }
        User actor = currentActor();
        return mfaService.adminReset(actor, target);
    }

    /**
     * PRD ADM-02: set a user's admin console role. Only SUPER_ADMIN may
     * call this, and only SUPER_ADMIN may grant SUPER_ADMIN to someone
     * else. Tenant admins cannot assign any admin role themselves — if
     * they could, any tenant admin could trivially escalate to
     * super-admin.
     */
    @Transactional
    public UserResponseDto setAdminRole(Long targetUserId, tech.cwvermaak.intellisso.model.AdminRole newRole) {
        tenantAccessor.requireSuperAdmin();
        if (newRole == null) {
            throw new IllegalArgumentException("adminRole is required");
        }
        User target = userRepository.findById(targetUserId)
                .orElseThrow(() -> new EntityNotFoundException("User " + targetUserId + " not found"));

        target.setAdminRole(newRole);
        // Keep the legacy boolean in sync so code that still reads it
        // (DB queries, old JWTs) behaves consistently.
        target.setSuperAdmin(newRole == tech.cwvermaak.intellisso.model.AdminRole.SUPER_ADMIN);

        // Bump token version so any outstanding access token is invalidated
        // — role changes take effect on the user's next request.
        target.setTokenVersion(target.getTokenVersion() + 1);
        userRepository.save(target);

        User actor = currentActor();
        auditService.recordAdmin("admin.role.assigned", actor,
                AuditEventTypes.TARGET_USER, String.valueOf(target.getId()),
                AuditService.meta(
                        "target_email", target.getEmail(),
                        "new_role", newRole.name(),
                        "tenant", target.getTenant() != null ? target.getTenant().getSlug() : null));
        return toDto(target);
    }

    private User currentActor() {
        // The JwtAuthenticationFilter sets the principal to the caller's
        // email; look them up in the current tenant so audit rows carry
        // an accurate actor_user_id.
        String tenantSlug = tech.cwvermaak.intellisso.config.tenant.TenantContext.get();
        Object principal = org.springframework.security.core.context.SecurityContextHolder
                .getContext().getAuthentication() == null ? null
                : org.springframework.security.core.context.SecurityContextHolder
                        .getContext().getAuthentication().getPrincipal();
        if (tenantSlug == null || !(principal instanceof String email)) return null;
        return userRepository.findByTenant_SlugAndEmailIgnoreCase(tenantSlug, email).orElse(null);
    }

    // -------- Environments --------------------------------------------

    public List<EnvironmentDto> listEnvironments() {
        Long tid = tenantAccessor.requireTenantId();
        return environmentRepository.findByTenantId(tid).stream()
                .map(AdminService::toDto)
                .toList();
    }

    @Transactional
    public EnvironmentDto createEnvironment(EnvironmentDto dto) {
        if (dto.getName() == null || dto.getName().isBlank()) {
            throw new IllegalArgumentException("Environment name is required");
        }
        Tenant tenant = tenantAccessor.requireTenant();
        Environment e = Environment.builder()
                .tenant(tenant)
                .name(dto.getName().trim())
                .projectName(dto.getProjectName())
                .description(dto.getDescription())
                .build();
        return toDto(environmentRepository.save(e));
    }

    @Transactional
    public EnvironmentDto updateEnvironment(Long id, EnvironmentDto dto) {
        Long tid = tenantAccessor.requireTenantId();
        Environment e = environmentRepository.findByIdAndTenantId(id, tid)
                .orElseThrow(() -> new EntityNotFoundException("Environment " + id + " not found"));
        if (dto.getName() != null) e.setName(dto.getName());
        if (dto.getProjectName() != null) e.setProjectName(dto.getProjectName());
        if (dto.getDescription() != null) e.setDescription(dto.getDescription());
        return toDto(e);
    }

    @Transactional
    public void deleteEnvironment(Long id) {
        Long tid = tenantAccessor.requireTenantId();
        Environment e = environmentRepository.findByIdAndTenantId(id, tid)
                .orElseThrow(() -> new EntityNotFoundException("Environment " + id + " not found"));
        environmentRepository.delete(e);
    }

    // -------- App clients ---------------------------------------------

    public List<AppClientDto> listAppClients() {
        Long tid = tenantAccessor.requireTenantId();
        return appClientRepository.findByTenantId(tid).stream()
                .map(AdminService::toDtoMasked)
                .toList();
    }

    @Transactional
    public AppClientDto createAppClient(AppClientDto dto) {
        if (dto.getClientName() == null || dto.getClientName().isBlank()) {
            throw new IllegalArgumentException("clientName is required");
        }
        Tenant tenant = tenantAccessor.requireTenant();
        String apiKey = generateApiKey();
        AppClient c = AppClient.builder()
                .tenant(tenant)
                .clientName(dto.getClientName().trim())
                .apiKey(apiKey)
                .enabled(dto.getEnabled() == null ? true : dto.getEnabled())
                .build();
        AppClient saved = appClientRepository.save(c);
        // Return the key in the clear ONCE on creation so the admin can copy it.
        return AppClientDto.builder()
                .id(saved.getId())
                .clientName(saved.getClientName())
                .apiKey(apiKey)
                .enabled(saved.isEnabled())
                .build();
    }

    @Transactional
    public AppClientDto updateAppClient(Long id, AppClientDto dto) {
        Long tid = tenantAccessor.requireTenantId();
        AppClient c = appClientRepository.findByIdAndTenantId(id, tid)
                .orElseThrow(() -> new EntityNotFoundException("App client " + id + " not found"));
        if (dto.getClientName() != null) c.setClientName(dto.getClientName());
        if (dto.getEnabled() != null) c.setEnabled(dto.getEnabled());
        return toDtoMasked(c);
    }

    @Transactional
    public void deleteAppClient(Long id) {
        Long tid = tenantAccessor.requireTenantId();
        AppClient c = appClientRepository.findByIdAndTenantId(id, tid)
                .orElseThrow(() -> new EntityNotFoundException("App client " + id + " not found"));
        appClientRepository.delete(c);
    }

    // -------- Mapping + helpers ---------------------------------------

    private static RoleDto toDto(Role r) {
        return RoleDto.builder()
                .id(r.getId())
                .name(r.getName())
                .description(r.getDescription())
                .responsibilities(r.getResponsibilities() == null ? List.of() :
                        r.getResponsibilities().stream().map(Responsibility::getName).toList())
                .build();
    }

    private static UserResponseDto toDto(User u) {
        return UserResponseDto.builder()
                .id(u.getId())
                .name(u.getName())
                .email(u.getEmail())
                .imageUrl(u.getImageUrl())
                .provider(u.getProvider())
                .role(u.getRole() != null ? u.getRole().getName() : null)
                .adminRole(u.getAdminRole() != null ? u.getAdminRole() : tech.cwvermaak.intellisso.model.AdminRole.NONE)
                .build();
    }

    private static EnvironmentDto toDto(Environment e) {
        return EnvironmentDto.builder()
                .id(e.getId())
                .name(e.getName())
                .projectName(e.getProjectName())
                .description(e.getDescription())
                .build();
    }

    private static AppClientDto toDtoMasked(AppClient c) {
        String key = c.getApiKey();
        String masked = key == null || key.length() < 8
                ? "****"
                : key.substring(0, 4) + "…" + key.substring(key.length() - 4);
        return AppClientDto.builder()
                .id(c.getId())
                .clientName(c.getClientName())
                .apiKey(masked)
                .enabled(c.isEnabled())
                .build();
    }

    private static String generateApiKey() {
        byte[] buf = new byte[24];
        RNG.nextBytes(buf);
        return "wf_live_" + HexFormat.of().formatHex(buf);
    }
}
