package tech.cwvermaak.weldforge.service;

import jakarta.persistence.EntityNotFoundException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import tech.cwvermaak.weldforge.config.tenant.TenantAccessor;
import tech.cwvermaak.weldforge.model.*;
import tech.cwvermaak.weldforge.model.dto.GroupRoleMappingDto;
import tech.cwvermaak.weldforge.repository.GroupRoleMappingRepository;
import tech.cwvermaak.weldforge.repository.RoleRepository;
import tech.cwvermaak.weldforge.repository.ScimGroupRepository;
import tech.cwvermaak.weldforge.repository.TenantRepository;
import tech.cwvermaak.weldforge.repository.UserRepository;
import tech.cwvermaak.weldforge.service.audit.AuditEventTypes;
import tech.cwvermaak.weldforge.service.audit.AuditService;

import java.util.*;
import java.util.stream.Collectors;

/**
 * Manages the binding between SCIM Groups and application Roles.
 * When group membership changes (via SCIM or SAML provisioning),
 * {@link #applyMappings} re-evaluates the user's role based on
 * all active mappings for the tenant.
 *
 * Priority determines which role wins when a user belongs to
 * multiple mapped groups — lowest priority number = highest
 * precedence.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class GroupRoleMappingService {

    private final TenantAccessor tenantAccessor;
    private final GroupRoleMappingRepository mappingRepository;
    private final ScimGroupRepository scimGroupRepository;
    private final RoleRepository roleRepository;
    private final UserRepository userRepository;
    private final TenantRepository tenantRepository;
    private final AuditService auditService;

    // ---- CRUD -----------------------------------------------------------

    public List<GroupRoleMappingDto> list(Long tenantId) {
        tenantAccessor.requireAnyAdmin();
        tenantAccessor.requireSameTenant(tenantId);
        return mappingRepository.findByTenantId(tenantId).stream()
                .map(GroupRoleMappingService::toDto)
                .toList();
    }

    @Transactional
    public GroupRoleMappingDto create(Long tenantId, GroupRoleMappingDto dto) {
        tenantAccessor.requireTenantAdmin();
        tenantAccessor.requireSameTenant(tenantId);
        Tenant tenant = tenantRepository.findById(tenantId)
                .orElseThrow(() -> new EntityNotFoundException("Tenant " + tenantId + " not found"));
        if (dto.getScimGroupId() == null) throw new IllegalArgumentException("scimGroupId is required");
        if (dto.getRoleId() == null) throw new IllegalArgumentException("roleId is required");

        ScimGroup group = scimGroupRepository.findByIdAndTenantId(dto.getScimGroupId(), tenant.getId())
                .orElseThrow(() -> new EntityNotFoundException("SCIM group " + dto.getScimGroupId() + " not found"));
        Role role = roleRepository.findByIdAndTenantId(dto.getRoleId(), tenant.getId())
                .orElseThrow(() -> new EntityNotFoundException("Role " + dto.getRoleId() + " not found"));

        GroupRoleMapping mapping = GroupRoleMapping.builder()
                .tenant(tenant)
                .scimGroup(group)
                .role(role)
                .priority(dto.getPriority() != null ? dto.getPriority() : 0)
                .build();
        mappingRepository.save(mapping);

        auditService.recordAdmin(AuditEventTypes.GROUP_ROLE_MAPPING_CREATE, null,
                AuditEventTypes.TARGET_GROUP_ROLE_MAPPING, String.valueOf(mapping.getId()),
                AuditService.meta("group", group.getDisplayName(), "role", role.getName(),
                        "priority", mapping.getPriority()));

        return toDto(mapping);
    }

    @Transactional
    public void delete(Long tenantId, Long id) {
        tenantAccessor.requireTenantAdmin();
        tenantAccessor.requireSameTenant(tenantId);
        GroupRoleMapping mapping = mappingRepository.findByIdAndTenantId(id, tenantId)
                .orElseThrow(() -> new EntityNotFoundException("Mapping " + id + " not found"));
        mappingRepository.delete(mapping);

        auditService.recordAdmin(AuditEventTypes.GROUP_ROLE_MAPPING_DELETE, null,
                AuditEventTypes.TARGET_GROUP_ROLE_MAPPING, String.valueOf(id),
                AuditService.meta("group", mapping.getScimGroup().getDisplayName(),
                        "role", mapping.getRole().getName()));
    }

    // ---- Role resolution ------------------------------------------------

    /**
     * Given the user's SCIM group memberships, find the mapped role with
     * the highest priority (lowest number). Returns empty if no mappings
     * match any of the user's groups.
     */
    public Optional<Role> resolveRole(Long tenantId, Long userId) {
        User user = userRepository.findByIdAndTenantId(userId, tenantId).orElse(null);
        if (user == null) return Optional.empty();

        // Collect group IDs the user belongs to
        List<ScimGroup> tenantGroups = scimGroupRepository.findByTenantId(tenantId);
        Set<Long> userGroupIds = tenantGroups.stream()
                .filter(g -> g.getMembers().stream().anyMatch(u -> u.getId().equals(userId)))
                .map(ScimGroup::getId)
                .collect(Collectors.toSet());

        if (userGroupIds.isEmpty()) return Optional.empty();

        // Find mappings for those groups, ordered by priority
        List<GroupRoleMapping> mappings = mappingRepository
                .findByTenantIdAndScimGroupIdIn(tenantId, userGroupIds);

        return mappings.stream()
                .min(Comparator.comparingInt(GroupRoleMapping::getPriority))
                .map(GroupRoleMapping::getRole);
    }

    /**
     * Re-evaluate and apply the user's role based on group-role mappings.
     * Returns true if the user's role was changed.
     */
    @Transactional
    public boolean applyMappings(Long tenantId, Long userId) {
        User user = userRepository.findByIdAndTenantId(userId, tenantId).orElse(null);
        if (user == null) return false;

        Optional<Role> resolved = resolveRole(tenantId, userId);
        if (resolved.isEmpty()) return false;

        Role newRole = resolved.get();
        Role previousRole = user.getRole();

        if (previousRole != null && previousRole.getId().equals(newRole.getId())) {
            return false; // No change
        }

        user.setRole(newRole);
        userRepository.save(user);

        auditService.recordUserAction(AuditEventTypes.GROUP_ROLE_APPLY, user,
                AuditEventTypes.TARGET_USER, String.valueOf(user.getId()),
                AuditService.meta(
                        "previous_role", previousRole != null ? previousRole.getName() : null,
                        "new_role", newRole.getName()));

        log.info("Applied group-role mapping: user {} role changed from {} to {}",
                user.getEmail(),
                previousRole != null ? previousRole.getName() : "none",
                newRole.getName());

        return true;
    }

    // ---- Helpers --------------------------------------------------------

    static GroupRoleMappingDto toDto(GroupRoleMapping m) {
        return GroupRoleMappingDto.builder()
                .id(m.getId())
                .scimGroupId(m.getScimGroup().getId())
                .scimGroupName(m.getScimGroup().getDisplayName())
                .roleId(m.getRole().getId())
                .roleName(m.getRole().getName())
                .priority(m.getPriority())
                .build();
    }
}
