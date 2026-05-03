package tech.cwvermaak.weldforge.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import tech.cwvermaak.weldforge.model.TenantTwilioProvider;

import java.util.Optional;

public interface TenantTwilioProviderRepository extends JpaRepository<TenantTwilioProvider, Long> {

    Optional<TenantTwilioProvider> findByTenantId(Long tenantId);

    Optional<TenantTwilioProvider> findByTenantIdAndEnabledTrue(Long tenantId);

    void deleteByTenantId(Long tenantId);
}
