package tech.cwvermaak.intellisso.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import tech.cwvermaak.intellisso.model.TenantTwilioProvider;

import java.util.Optional;

public interface TenantTwilioProviderRepository extends JpaRepository<TenantTwilioProvider, Long> {

    Optional<TenantTwilioProvider> findByTenantId(Long tenantId);

    Optional<TenantTwilioProvider> findByTenantIdAndEnabledTrue(Long tenantId);

    void deleteByTenantId(Long tenantId);
}
