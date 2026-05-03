package tech.cwvermaak.weldforge.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import tech.cwvermaak.weldforge.model.RevokedOidcToken;

import java.util.Optional;

public interface RevokedOidcTokenRepository extends JpaRepository<RevokedOidcToken, Long> {

    Optional<RevokedOidcToken> findByTokenHash(String tokenHash);

    boolean existsByTokenHash(String tokenHash);
}
