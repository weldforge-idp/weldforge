package tech.cwvermaak.weldforge.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import tech.cwvermaak.weldforge.model.AppClient;

import java.util.List;
import java.util.Optional;

public interface AppClientRepository extends JpaRepository<AppClient, Long> {

    Optional<AppClient> findByApiKeyAndEnabledTrue(String apiKey);

    Optional<AppClient> findByApiKeyHashAndEnabledTrue(String apiKeyHash);

    List<AppClient> findByTenantId(Long tenantId);

    Optional<AppClient> findByIdAndTenantId(Long id, Long tenantId);
}
