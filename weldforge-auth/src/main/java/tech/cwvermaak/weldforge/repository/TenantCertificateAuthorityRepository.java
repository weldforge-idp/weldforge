package tech.cwvermaak.weldforge.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import tech.cwvermaak.weldforge.model.TenantCertificateAuthority;

import java.util.Optional;

public interface TenantCertificateAuthorityRepository
        extends JpaRepository<TenantCertificateAuthority, Long> {

    Optional<TenantCertificateAuthority> findByTenantId(Long tenantId);
}
