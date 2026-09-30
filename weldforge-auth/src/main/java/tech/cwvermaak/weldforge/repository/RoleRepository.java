package tech.cwvermaak.weldforge.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import tech.cwvermaak.weldforge.model.Role;

import java.util.List;
import java.util.Optional;

public interface RoleRepository extends JpaRepository<Role, Long> {

    List<Role> findByTenantId(Long tenantId);

    Optional<Role> findByIdAndTenantId(Long id, Long tenantId);

    Optional<Role> findByTenantIdAndNameIgnoreCase(Long tenantId, String name);

    boolean existsByTenantIdAndNameIgnoreCase(Long tenantId, String name);

    /**
     * Every role name this user holds, ordered so a token's {@code roles}
     * claim is stable between issues.
     *
     * <p>Queried rather than walked from {@code user.getRoles()} on purpose:
     * tokens are minted outside an explicit transaction, so reading a lazy
     * collection there would work only while {@code spring.jpa.open-in-view}
     * stays enabled. Disabling it is an ordinary hardening step, and it would
     * turn every token request into a 500.
     */
    @org.springframework.data.jpa.repository.Query(
            "select r.name from User u join u.roles r where u.id = :userId order by r.name")
    List<String> findRoleNamesByUserId(@org.springframework.data.repository.query.Param("userId") Long userId);

    /** How many users hold this role, so a delete can refuse with a reason. */
    @org.springframework.data.jpa.repository.Query(
            "select count(u) from User u join u.roles r where r.id = :roleId")
    long countUsersHolding(@org.springframework.data.repository.query.Param("roleId") Long roleId);

    /** The roles a user holds, for editing the set. */
    @org.springframework.data.jpa.repository.Query(
            "select r from User u join u.roles r where u.id = :userId order by r.name")
    List<Role> findRolesByUserId(@org.springframework.data.repository.query.Param("userId") Long userId);
}
