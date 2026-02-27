package tech.cwvermaak.intellisso.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import tech.cwvermaak.intellisso.model.AppClient;

import java.util.Optional;

public interface AppClientRepository extends JpaRepository<AppClient, Long> {
    Optional<AppClient> findByApiKeyAndEnabledTrue(String apiKey);
}