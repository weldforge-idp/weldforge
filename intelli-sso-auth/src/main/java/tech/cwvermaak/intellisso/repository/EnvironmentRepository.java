package tech.cwvermaak.intellisso.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import tech.cwvermaak.intellisso.model.Environment;

public interface EnvironmentRepository extends JpaRepository<Environment, Long> {
}