package tech.cwvermaak.weldforge.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import tech.cwvermaak.weldforge.model.TenantSamlProvider;

import java.util.List;
import java.util.Optional;

public interface TenantSamlProviderRepository extends JpaRepository<TenantSamlProvider, Long> {

    List<TenantSamlProvider> findByTenantId(Long tenantId);

    List<TenantSamlProvider> findByTenantIdAndEnabledTrue(Long tenantId);

    Optional<TenantSamlProvider> findByTenantIdAndProviderKey(Long tenantId, String providerKey);

    Optional<TenantSamlProvider> findByTenant_SlugAndProviderKeyAndEnabledTrue(
            String tenantSlug, String providerKey);

    List<TenantSamlProvider> findByTenant_SlugAndEnabledTrue(String tenantSlug);
}
