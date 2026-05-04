package tech.cwvermaak.weldforge.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import tech.cwvermaak.weldforge.model.User;

import java.util.List;
import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {

    List<User> findByTenantId(Long tenantId);

    Optional<User> findByIdAndTenantId(Long id, Long tenantId);

    Optional<User> findByTenantIdAndEmailIgnoreCase(Long tenantId, String email);

    Optional<User> findByTenantIdAndUsernameIgnoreCase(Long tenantId, String username);

    Optional<User> findByTenantIdAndCellPhoneNumber(Long tenantId, String cellPhoneNumber);

    Optional<User> findByTenantIdAndProviderId(Long tenantId, String providerId);

    Optional<User> findByTenant_SlugAndEmailIgnoreCase(String tenantSlug, String email);

    Optional<User> findFirstByEmailIgnoreCase(String email);

    default Optional<User> findByTenantAndIdentifier(Long tenantId, String identifier) {
        return findByTenantIdAndEmailIgnoreCase(tenantId, identifier)
                .or(() -> findByTenantIdAndUsernameIgnoreCase(tenantId, identifier));
    }
}
