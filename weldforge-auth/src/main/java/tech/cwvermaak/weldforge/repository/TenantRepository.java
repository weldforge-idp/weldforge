package tech.cwvermaak.weldforge.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import tech.cwvermaak.weldforge.model.Tenant;

import java.util.List;
import java.util.Optional;

public interface TenantRepository extends JpaRepository<Tenant, Long> {
    Optional<Tenant> findBySlug(String slug);
    boolean existsBySlug(String slug);

    /** V2b review queue — tenants the domain gate declined (partial-indexed). */
    List<Tenant> findByVerificationReviewRequiredTrue();
}
