package tech.cwvermaak.weldforge.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import tech.cwvermaak.weldforge.model.OidcScope;

import java.util.List;
import java.util.Optional;

public interface OidcScopeRepository extends JpaRepository<OidcScope, Long> {

    List<OidcScope> findByTenantIdOrderByNameAsc(Long tenantId);

    Optional<OidcScope> findByTenantIdAndName(Long tenantId, String name);

    void deleteByTenantIdAndName(Long tenantId, String name);
}
