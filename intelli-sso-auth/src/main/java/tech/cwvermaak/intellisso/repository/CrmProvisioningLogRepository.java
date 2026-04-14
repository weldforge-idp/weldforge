package tech.cwvermaak.intellisso.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import tech.cwvermaak.intellisso.model.CrmProvisioningLog;

import java.util.List;
import java.util.Optional;

public interface CrmProvisioningLogRepository extends JpaRepository<CrmProvisioningLog, Long> {

    Optional<CrmProvisioningLog> findByProviderIdAndUserId(Long providerId, Long userId);

    Optional<CrmProvisioningLog> findByProviderIdAndMatchKeyValue(Long providerId, String matchKeyValue);

    List<CrmProvisioningLog> findByTenantId(Long tenantId);
}
