package tech.cwvermaak.intellisso.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import tech.cwvermaak.intellisso.model.TenantSigningKey;

import java.util.List;
import java.util.Optional;

public interface TenantSigningKeyRepository extends JpaRepository<TenantSigningKey, Long> {

    Optional<TenantSigningKey> findFirstByTenantIdAndActiveTrue(Long tenantId);

    Optional<TenantSigningKey> findByKid(String kid);

    /** Every key (active or not) for the JWKS — verifiers need recently-rotated keys too. */
    List<TenantSigningKey> findByTenantId(Long tenantId);
}
