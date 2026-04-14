package tech.cwvermaak.intellisso.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import tech.cwvermaak.intellisso.model.TenantCrmProvider;

import java.util.List;
import java.util.Optional;

public interface TenantCrmProviderRepository extends JpaRepository<TenantCrmProvider, Long> {

    List<TenantCrmProvider> findByTenantId(Long tenantId);

    List<TenantCrmProvider> findByTenantIdAndEnabledTrue(Long tenantId);

    Optional<TenantCrmProvider> findByIdAndTenantId(Long id, Long tenantId);
}
