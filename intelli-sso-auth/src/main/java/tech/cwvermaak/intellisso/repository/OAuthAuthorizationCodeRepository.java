package tech.cwvermaak.intellisso.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import tech.cwvermaak.intellisso.model.OAuthAuthorizationCode;

import java.util.Optional;

public interface OAuthAuthorizationCodeRepository extends JpaRepository<OAuthAuthorizationCode, Long> {

    Optional<OAuthAuthorizationCode> findByCodeHash(String codeHash);
}
