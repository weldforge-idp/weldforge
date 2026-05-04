package tech.cwvermaak.weldforge.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import tech.cwvermaak.weldforge.model.ScimGroup;

import java.util.List;
import java.util.Optional;

public interface ScimGroupRepository extends JpaRepository<ScimGroup, Long> {

    List<ScimGroup> findByTenantId(Long tenantId);

    Optional<ScimGroup> findByIdAndTenantId(Long id, Long tenantId);

    Optional<ScimGroup> findByTenantIdAndNameIgnoreCase(Long tenantId, String name);

    Optional<ScimGroup> findByTenantIdAndExternalId(Long tenantId, String externalId);

    boolean existsByTenantIdAndNameIgnoreCase(Long tenantId, String name);
}
