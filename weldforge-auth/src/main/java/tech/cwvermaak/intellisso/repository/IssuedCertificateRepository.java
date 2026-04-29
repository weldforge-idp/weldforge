package tech.cwvermaak.intellisso.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import tech.cwvermaak.intellisso.model.IssuedCertificate;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

public interface IssuedCertificateRepository extends JpaRepository<IssuedCertificate, Long> {

    List<IssuedCertificate> findByTenantId(Long tenantId);

    Optional<IssuedCertificate> findBySerialNumber(String serialNumber);

    Optional<IssuedCertificate> findByTenantIdAndSerialNumber(Long tenantId, String serialNumber);

    Optional<IssuedCertificate> findByFingerprintSha256(String fingerprintSha256);

    List<IssuedCertificate> findByTenantIdAndStatus(Long tenantId, IssuedCertificate.Status status);

    /** Used by the renewal notifier — window cadence from X50-04. */
    List<IssuedCertificate> findByStatusAndExpiresAtBetween(
            IssuedCertificate.Status status, LocalDateTime from, LocalDateTime to);
}
