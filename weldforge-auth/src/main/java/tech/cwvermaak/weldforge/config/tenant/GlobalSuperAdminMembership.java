package tech.cwvermaak.weldforge.config.tenant;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import tech.cwvermaak.weldforge.model.AdminMembership;
import tech.cwvermaak.weldforge.model.AdminRole;
import tech.cwvermaak.weldforge.model.User;
import tech.cwvermaak.weldforge.repository.AdminMembershipRepository;

import java.util.List;

/**
 * Keeps a user's global {@code SUPER_ADMIN} membership in step with their
 * super-admin flags, so there is one answer to "is this a super-admin?".
 *
 * <p>Two things read that answer. The JWT's {@code sa}/{@code adm} claims come
 * from the user row and drive the admin portal (the tenant picker) and every
 * {@code requireSuperAdmin()} check. Cross-tenant reach -- which tenant an
 * admin call may act in -- comes from {@code admin_membership}
 * ({@link TenantAccessor#effectiveRole}). Until 2026-09-11 nothing wrote the
 * membership, so a super-admin saw a picker the backend would not honour.
 * V57 back-filled the rows; every path that grants or removes super-admin goes
 * through here so they cannot drift apart again.
 *
 * <p>The flag rule is the same one the portal and V57 use:
 * {@code is_super_admin OR admin_role = SUPER_ADMIN}.
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class GlobalSuperAdminMembership {

    private final AdminMembershipRepository memberships;

    public static boolean flaggedSuperAdmin(User user) {
        return user.isSuperAdmin() || user.getAdminRole() == AdminRole.SUPER_ADMIN;
    }

    /** Grant or revoke the global row so it matches {@link #flaggedSuperAdmin}. */
    public void sync(User user, Long grantedBy) {
        if (flaggedSuperAdmin(user)) {
            grant(user, grantedBy);
        } else {
            revoke(user);
        }
    }

    /** Idempotent. Returns true when a row was created. */
    public boolean grant(User user, Long grantedBy) {
        if (!globalRows(user).isEmpty()) return false;
        memberships.save(AdminMembership.builder()
                .user(user)
                .tenant(null)
                .adminRole(AdminRole.SUPER_ADMIN)
                .grantedBy(grantedBy)
                .build());
        log.info("Granted global SUPER_ADMIN membership to user {}", user.getId());
        return true;
    }

    /**
     * Removes the global row. A demoted super-admin keeps no cross-tenant
     * reach; per-tenant memberships are left alone. Returns rows removed.
     */
    public int revoke(User user) {
        List<AdminMembership> rows = globalRows(user);
        if (rows.isEmpty()) return 0;
        memberships.deleteAll(rows);
        log.info("Revoked global SUPER_ADMIN membership from user {}", user.getId());
        return rows.size();
    }

    private List<AdminMembership> globalRows(User user) {
        if (user.getId() == null) return List.of();
        return memberships.findByUser_Id(user.getId()).stream()
                .filter(m -> m.isGlobal() && m.getAdminRole() == AdminRole.SUPER_ADMIN)
                .toList();
    }
}
