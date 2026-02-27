package tech.cwvermaak.intellisso.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import tech.cwvermaak.intellisso.model.Role;

import java.util.Optional;

public interface RoleRepository extends JpaRepository<Role, Long> {
    Optional<Role> findByName(String name);
}