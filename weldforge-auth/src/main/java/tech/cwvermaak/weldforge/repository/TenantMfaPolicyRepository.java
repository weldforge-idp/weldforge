package tech.cwvermaak.weldforge.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import tech.cwvermaak.weldforge.model.TenantMfaPolicy;

import java.util.Optional;

public interface TenantMfaPolicyRepository extends JpaRepository<TenantMfaPolicy, Long> {

    Optional<TenantMfaPolicy> findByTenantId(Long tenantId);
}
