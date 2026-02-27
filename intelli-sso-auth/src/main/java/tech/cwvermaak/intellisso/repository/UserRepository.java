package tech.cwvermaak.intellisso.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import tech.cwvermaak.intellisso.model.User;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByEmail(String email);
    Optional<User> findByUsername(String username);
    Optional<User> findByUsernameOrEmail(String username, String email);
    Optional<User> findByProviderAndProviderId(String provider, String providerId);
}
