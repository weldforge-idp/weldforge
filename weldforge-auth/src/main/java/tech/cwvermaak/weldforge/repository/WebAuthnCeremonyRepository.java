package tech.cwvermaak.weldforge.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import tech.cwvermaak.weldforge.model.WebAuthnCeremony;

import java.time.LocalDateTime;

public interface WebAuthnCeremonyRepository extends JpaRepository<WebAuthnCeremony, String> {

    /** Prune ceremonies nobody completed. */
    long deleteByExpiresAtBefore(LocalDateTime cutoff);
}
