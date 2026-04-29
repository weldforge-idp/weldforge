package tech.cwvermaak.intellisso.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import tech.cwvermaak.intellisso.model.RevokedOidcToken;

import java.util.Optional;

public interface RevokedOidcTokenRepository extends JpaRepository<RevokedOidcToken, Long> {

    Optional<RevokedOidcToken> findByTokenHash(String tokenHash);

    boolean existsByTokenHash(String tokenHash);
}
