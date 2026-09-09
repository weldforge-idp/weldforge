package tech.cwvermaak.weldforge.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import tech.cwvermaak.weldforge.model.OidcConsentGrant;

import java.util.Optional;

public interface OidcConsentGrantRepository extends JpaRepository<OidcConsentGrant, Long> {

    Optional<OidcConsentGrant> findByUserIdAndClientId(Long userId, Long clientId);
}
