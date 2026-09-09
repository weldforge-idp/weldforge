package tech.cwvermaak.weldforge.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import tech.cwvermaak.weldforge.model.SamlRequestReplay;

import java.time.LocalDateTime;

public interface SamlRequestReplayRepository extends JpaRepository<SamlRequestReplay, String> {

    /** Prune request IDs whose freshness window has passed. */
    long deleteByExpiresAtBefore(LocalDateTime cutoff);
}
