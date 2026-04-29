package tech.cwvermaak.intellisso.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import tech.cwvermaak.intellisso.model.Role;

import java.util.List;
import java.util.Optional;

public interface RoleRepository extends JpaRepository<Role, Long> {

    List<Role> findByTenantId(Long tenantId);

    Optional<Role> findByIdAndTenantId(Long id, Long tenantId);

    Optional<Role> findByTenantIdAndNameIgnoreCase(Long tenantId, String name);

    boolean existsByTenantIdAndNameIgnoreCase(Long tenantId, String name);
}
