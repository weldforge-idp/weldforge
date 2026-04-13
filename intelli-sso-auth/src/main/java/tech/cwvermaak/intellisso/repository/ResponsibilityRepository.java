package tech.cwvermaak.intellisso.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import tech.cwvermaak.intellisso.model.Responsibility;

import java.util.List;

public interface ResponsibilityRepository extends JpaRepository<Responsibility, Long> {

    List<Responsibility> findByRole_TenantId(Long tenantId);
}
