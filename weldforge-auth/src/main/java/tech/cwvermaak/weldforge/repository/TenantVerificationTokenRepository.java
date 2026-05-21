package tech.cwvermaak.weldforge.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import tech.cwvermaak.weldforge.model.TenantVerificationToken;

import java.time.LocalDateTime;
import java.util.Optional;

public interface TenantVerificationTokenRepository
        extends JpaRepository<TenantVerificationToken, Long> {

    Optional<TenantVerificationToken> findByTokenHash(String tokenHash);

    /**
     * Invalidate every still-pending token for a tenant. Called when a
     * fresh challenge is issued so a single tenant can have at most one
     * live token at a time — closes the "spray N pending tokens, race
     * to consume the one that lands" attack pattern.
     */
    @Modifying
    @Query("""
        update TenantVerificationToken t
        set t.usedAt = :now
        where t.tenant.id = :tenantId
          and t.usedAt is null
          and t.expiresAt > :now
        """)
    int invalidatePendingForTenant(@Param("tenantId") Long tenantId,
                                   @Param("now")      LocalDateTime now);
}
