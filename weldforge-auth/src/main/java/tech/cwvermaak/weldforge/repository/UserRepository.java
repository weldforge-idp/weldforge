package tech.cwvermaak.weldforge.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
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

    /**
     * Seats consumed in a tenant. Deactivated users are excluded, so
     * deactivating somebody frees a seat rather than burning it for good.
     * Drives {@code TenantSeatService}.
     */
    long countByTenantIdAndActiveTrue(Long tenantId);

    /**
     * Seats consumed by everyone <em>except</em> the given user. Used when
     * checking whether a currently-inactive user can be reactivated: the
     * caller may already have flipped {@code active} on the in-memory entity,
     * and Hibernate's auto-flush would then include it in a plain count,
     * making the tenant look one seat fuller than it is.
     */
    long countByTenantIdAndActiveTrueAndIdNot(Long tenantId, Long userId);

    /**
     * Atomically bump every user's {@code token_version} in a tenant.
     * Called when the tenant is being deleted: any outstanding access JWT
     * carries a {@code ver} lower than the post-bump value and stops
     * authenticating at {@code JwtAuthenticationFilter}.
     */
    @Modifying
    @Query("update User u set u.tokenVersion = u.tokenVersion + 1 where u.tenant.id = :tenantId")
    int bumpTokenVersionForTenant(@Param("tenantId") Long tenantId);
}
