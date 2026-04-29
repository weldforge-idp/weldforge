package tech.cwvermaak.intellisso.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import tech.cwvermaak.intellisso.model.GroupRoleMapping;

import java.util.Collection;
import java.util.List;
import java.util.Optional;

public interface GroupRoleMappingRepository extends JpaRepository<GroupRoleMapping, Long> {

    List<GroupRoleMapping> findByTenantId(Long tenantId);

    List<GroupRoleMapping> findByTenantIdAndScimGroupIdIn(Long tenantId, Collection<Long> groupIds);

    Optional<GroupRoleMapping> findByIdAndTenantId(Long id, Long tenantId);
}
