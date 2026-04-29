package tech.cwvermaak.intellisso.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import tech.cwvermaak.intellisso.model.TenantCertificateAuthority;

import java.util.Optional;

public interface TenantCertificateAuthorityRepository
        extends JpaRepository<TenantCertificateAuthority, Long> {

    Optional<TenantCertificateAuthority> findByTenantId(Long tenantId);
}
