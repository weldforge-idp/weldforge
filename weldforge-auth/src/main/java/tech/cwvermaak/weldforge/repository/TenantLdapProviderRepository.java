package tech.cwvermaak.weldforge.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import tech.cwvermaak.weldforge.model.TenantLdapProvider;

import java.util.List;
import java.util.Optional;

public interface TenantLdapProviderRepository extends JpaRepository<TenantLdapProvider, Long> {

    List<TenantLdapProvider> findByTenantId(Long tenantId);

    List<TenantLdapProvider> findByTenantIdAndEnabledTrue(Long tenantId);

    Optional<TenantLdapProvider> findByIdAndTenantId(Long id, Long tenantId);
}
