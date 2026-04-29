package tech.cwvermaak.intellisso.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import tech.cwvermaak.intellisso.model.SamlServiceProvider;

import java.util.List;
import java.util.Optional;

public interface SamlServiceProviderRepository extends JpaRepository<SamlServiceProvider, Long> {

    List<SamlServiceProvider> findByTenantId(Long tenantId);

    List<SamlServiceProvider> findByTenantIdAndEnabledTrue(Long tenantId);

    Optional<SamlServiceProvider> findByTenantIdAndEntityId(Long tenantId, String entityId);

    Optional<SamlServiceProvider> findByIdAndTenantId(Long id, Long tenantId);
}
