package tech.cwvermaak.weldforge.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import tech.cwvermaak.weldforge.model.AdminMembership;

import java.util.List;
import java.util.Optional;

/**
 * Admin memberships for cross-tenant authorization. A caller's effective
 * role is derived from these rows — see {@code TenantAccessor.effectiveRole}.
 */
public interface AdminMembershipRepository extends JpaRepository<AdminMembership, Long> {

    /** Every membership held by a user — per-tenant rows plus the optional global row. */
    List<AdminMembership> findByUser_Id(Long userId);

    Optional<AdminMembership> findByIdAndUser_Id(Long id, Long userId);
}
