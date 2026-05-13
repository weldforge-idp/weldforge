package tech.cwvermaak.weldforge.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import tech.cwvermaak.weldforge.model.TenantHost;

import java.util.Optional;

public interface TenantHostRepository extends JpaRepository<TenantHost, String> {

    Optional<TenantHost> findByHostIgnoreCase(String host);
}
