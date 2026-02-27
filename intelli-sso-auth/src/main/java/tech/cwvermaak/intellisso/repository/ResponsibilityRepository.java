package tech.cwvermaak.intellisso.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import tech.cwvermaak.intellisso.model.Responsibility;

public interface ResponsibilityRepository extends JpaRepository<Responsibility, Long> {
}