package tech.cwvermaak.weldforge.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import tech.cwvermaak.weldforge.model.TenantSlugHoldback;

import java.util.Optional;

public interface TenantSlugHoldbackRepository extends JpaRepository<TenantSlugHoldback, Long> {

    /**
     * Most recent release record for a slug. {@link Optional#empty()} when
     * the slug has never been released — i.e. it has never been a tenant,
     * or the tenant still exists. The caller compares
     * {@code releasedAt + holdbackWindow} against {@code now} to decide
     * whether the slug is still on holdback.
     */
    Optional<TenantSlugHoldback> findFirstBySlugOrderByReleasedAtDesc(String slug);
}
