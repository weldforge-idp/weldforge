package tech.cwvermaak.weldforge.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import tech.cwvermaak.weldforge.model.OidcClient;

import java.util.List;
import java.util.Optional;

public interface OidcClientRepository extends JpaRepository<OidcClient, Long> {

    List<OidcClient> findByTenantId(Long tenantId);

    Optional<OidcClient> findByIdAndTenantId(Long id, Long tenantId);

    Optional<OidcClient> findByTenantIdAndClientId(Long tenantId, String clientId);

    Optional<OidcClient> findByTenant_SlugAndClientId(String tenantSlug, String clientId);
}
