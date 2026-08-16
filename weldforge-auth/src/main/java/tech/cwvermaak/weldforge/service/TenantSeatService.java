package tech.cwvermaak.weldforge.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import tech.cwvermaak.weldforge.model.Tenant;
import tech.cwvermaak.weldforge.model.User;
import tech.cwvermaak.weldforge.repository.UserRepository;

/**
 * Enforces the per-tenant seat cap ({@link Tenant#getMaxUsers()}).
 *
 * <p>Every path that creates a {@code users} row calls
 * {@link #assertCapacity(Tenant)} first — there are six of them, including
 * three just-in-time paths that provision during login (social, LDAP, SAML).
 * The check is deliberately an explicit call at each site rather than a JPA
 * lifecycle hook: a {@code @PrePersist} would be invisible at the call site
 * and gives no clean way to turn a violation into the right per-protocol
 * error.
 *
 * <p>Seats count <em>active</em> users only, so deactivating a user frees a
 * seat. A null {@code maxUsers} means unlimited, which is the default and
 * what every tenant predating the free tier carries — so this class is a
 * no-op for them beyond a null check.
 *
 * <p><strong>Race note.</strong> The count-then-insert is not atomic: two
 * concurrent creations at exactly {@code limit - 1} seats can both pass. That
 * is accepted — the failure mode is one seat of overshoot on a plan
 * boundary, not a security or billing integrity problem, and closing it would
 * cost a lock on every user creation. If it ever matters, the durable fix is
 * a database trigger (see {@code docs/free-tier-onboarding-plan.md}).
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class TenantSeatService {

    private final UserRepository userRepository;

    /**
     * Throw if the tenant has no seat free for one more active user.
     *
     * @throws SeatLimitExceededException when the cap is already met or
     *                                    exceeded
     */
    @Transactional(readOnly = true)
    public void assertCapacity(Tenant tenant) {
        if (tenant == null || tenant.getMaxUsers() == null) {
            return; // unlimited
        }
        int limit = tenant.getMaxUsers();
        long current = userRepository.countByTenantIdAndActiveTrue(tenant.getId());
        if (current >= limit) {
            log.info("Seat cap reached for tenant {} ({}/{})", tenant.getSlug(), current, limit);
            throw new SeatLimitExceededException(tenant.getSlug(), limit, current);
        }
    }

    /**
     * Throw if reactivating a currently-inactive user would push the tenant
     * past its cap. A no-op unless the user is genuinely transitioning
     * inactive → active.
     *
     * <p>Guarding creation alone is not enough: a tenant at its cap could
     * otherwise deactivate five users, create five new ones, then reactivate
     * the original five and sit permanently over the limit.
     *
     * <p>Counts every active user <em>except</em> this one, so it is correct
     * whether or not the caller has already flipped the flag on the entity.
     *
     * @param wasActive the user's {@code active} state before the caller
     *                  began mutating it
     */
    @Transactional(readOnly = true)
    public void assertCapacityForActivation(Tenant tenant, User user, boolean wasActive) {
        if (wasActive || !user.isActive()) {
            return; // not a reactivation
        }
        if (tenant == null || tenant.getMaxUsers() == null) {
            return; // unlimited
        }
        int limit = tenant.getMaxUsers();
        long others = userRepository.countByTenantIdAndActiveTrueAndIdNot(tenant.getId(), user.getId());
        if (others + 1 > limit) {
            log.info("Seat cap blocks reactivation of user {} in tenant {} ({}/{})",
                    user.getId(), tenant.getSlug(), others + 1, limit);
            throw new SeatLimitExceededException(tenant.getSlug(), limit, others);
        }
    }

    /**
     * Seats in use / available, for the admin portal's usage indicator.
     * {@code limit} is null when the tenant is uncapped.
     */
    @Transactional(readOnly = true)
    public SeatUsage usage(Tenant tenant) {
        long used = userRepository.countByTenantIdAndActiveTrue(tenant.getId());
        return new SeatUsage(used, tenant.getMaxUsers());
    }

    /**
     * @param used  active users in the tenant right now
     * @param limit seat cap, or null when unlimited
     */
    public record SeatUsage(long used, Integer limit) {

        /** Fraction of the cap consumed, 0.0–1.0+; null when uncapped. */
        public Double fractionUsed() {
            return limit == null ? null : (double) used / limit;
        }

        /** True once the tenant is at or past 80% of its cap. */
        public boolean nearingLimit() {
            Double f = fractionUsed();
            return f != null && f >= 0.8d;
        }

        public boolean atLimit() {
            return limit != null && used >= limit;
        }
    }
}
