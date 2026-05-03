package tech.cwvermaak.weldforge.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import tech.cwvermaak.weldforge.model.Responsibility;

import java.util.List;

public interface ResponsibilityRepository extends JpaRepository<Responsibility, Long> {

    List<Responsibility> findByRole_TenantId(Long tenantId);
}
