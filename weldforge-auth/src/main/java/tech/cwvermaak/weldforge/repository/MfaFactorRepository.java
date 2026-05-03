package tech.cwvermaak.weldforge.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import tech.cwvermaak.weldforge.model.MfaFactor;
import tech.cwvermaak.weldforge.model.MfaFactorType;

import java.util.List;
import java.util.Optional;

public interface MfaFactorRepository extends JpaRepository<MfaFactor, Long> {

    List<MfaFactor> findByUserId(Long userId);

    List<MfaFactor> findByUserIdAndEnabledTrueAndVerifiedTrue(Long userId);

    List<MfaFactor> findByUserIdAndType(Long userId, MfaFactorType type);

    Optional<MfaFactor> findByIdAndUserId(Long id, Long userId);

    Optional<MfaFactor> findByCredentialId(String credentialId);
}
