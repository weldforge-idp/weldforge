package tech.cwvermaak.weldforge.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import tech.cwvermaak.weldforge.model.ServiceAccount;

import java.util.List;
import java.util.Optional;

public interface ServiceAccountRepository extends JpaRepository<ServiceAccount, Long> {

    List<ServiceAccount> findByTenantId(Long tenantId);

    Optional<ServiceAccount> findByIdAndTenantId(Long id, Long tenantId);

    Optional<ServiceAccount> findByTokenHashAndEnabledTrue(String tokenHash);
}
