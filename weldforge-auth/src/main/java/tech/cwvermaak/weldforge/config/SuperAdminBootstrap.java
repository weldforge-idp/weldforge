package tech.cwvermaak.weldforge.config;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;
import tech.cwvermaak.weldforge.config.tenant.GlobalSuperAdminMembership;
import tech.cwvermaak.weldforge.model.AdminRole;
import tech.cwvermaak.weldforge.model.User;
import tech.cwvermaak.weldforge.repository.UserRepository;

import java.util.List;

/**
 * One-time bootstrap: if {@code APP_ADMIN_BOOTSTRAP_SUPER_ADMIN_EMAIL} is set
 * and exactly one user holds that email -- in the tenant named by
 * {@code APP_ADMIN_BOOTSTRAP_SUPER_ADMIN_TENANT}, or across all tenants when
 * that is unset -- promote them to super admin. Once any super admin exists the
 * account must also have a verified address.
 *
 * <p>This exists so a freshly-installed system can be bootstrapped without
 * a manual UPDATE against the database — nothing seeds an admin user, so on a
 * fresh install the first account must register through the normal flow and
 * then be promoted here.
 *
 * <p>The environment variable is the relaxed-binding form of the property
 * {@code app.admin.bootstrap-super-admin-email}. An earlier version of this
 * comment named {@code APP_BOOTSTRAP_SUPER_ADMIN_EMAIL}, which binds to
 * nothing and silently does no promoting at all.
 *
 * <p>Promotion must set {@code adminRole}, not merely the legacy
 * {@code is_super_admin} boolean: {@code AuthService} stamps the JWT
 * {@code adm} claim from {@code adminRole}, and
 * {@code JwtAuthenticationFilter} prefers that claim over the boolean. Setting
 * the boolean alone produced a user who looked promoted in the database and
 * was refused by every super-admin endpoint.
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class SuperAdminBootstrap implements ApplicationRunner {

    @Value("${app.admin.bootstrap-super-admin-email:}")
    private String bootstrapEmail;

    /**
     * The tenant the bootstrap account lives in ({@code APP_ADMIN_BOOTSTRAP_SUPER_ADMIN_TENANT}).
     * Optional, but set it: an address is unique only within a tenant, so
     * without it the bootstrap can only act when exactly one account in the
     * whole system holds the address.
     */
    @Value("${app.admin.bootstrap-super-admin-tenant:}")
    private String bootstrapTenant;

    private final UserRepository userRepository;
    private final GlobalSuperAdminMembership globalMembership;

    /**
     * One transaction for the lookup, the promotion and the membership. Without
     * it the user came back detached, and the promotion's log line, reading the
     * lazy tenant, threw LazyInitializationException after the promotion had
     * been saved: startup failed, the global membership was never granted, and
     * production went down for a minute on 2026-10-19 until the restart found
     * the user already promoted.
     */
    @Override
    @Transactional
    public void run(ApplicationArguments args) {
        if (bootstrapEmail == null || bootstrapEmail.isBlank()) return;
        String email = bootstrapEmail.trim();
        String tenant = bootstrapTenant == null || bootstrapTenant.isBlank() ? null : bootstrapTenant.trim();

        // Never pick "the first" account with the address. An address is
        // unique only per tenant, so anyone who could register it in any
        // tenant with sign-up open created a row that a later restart might
        // promote -- the lookup had no tenant, no order and no verification
        // check, and ran on every start. Name the tenant, or the address must
        // be unambiguous across the whole system.
        List<User> matches = tenant != null
                ? userRepository.findByTenant_SlugAndEmailIgnoreCase(tenant, email).map(List::of).orElse(List.of())
                : userRepository.findAllByEmailIgnoreCase(email);

        if (matches.isEmpty()) {
            log.warn("Bootstrap super-admin email {} does not match any existing user{} — "
                    + "create the user first, then restart.", email, tenant != null ? " in tenant " + tenant : "");
            return;
        }
        if (matches.size() > 1) {
            log.warn("Bootstrap super-admin email {} is held by {} accounts in different tenants; promoting none. "
                    + "Set APP_ADMIN_BOOTSTRAP_SUPER_ADMIN_TENANT to the tenant the account lives in.",
                    email, matches.size());
            return;
        }
        promote(matches.get(0));
    }

    private void promote(User user) {
        boolean alreadyPromoted = user.isSuperAdmin() && user.getAdminRole() == AdminRole.SUPER_ADMIN;
        // Once any super admin exists, the bootstrap is a recovery path, not a
        // first run, and the account must have proved it controls the address.
        // On a fresh install nothing can be verified yet without mail, and
        // there is no existing authority to protect, so the first promotion is
        // allowed unverified.
        if (!alreadyPromoted && !user.isEmailVerified()
                && userRepository.existsByAdminRole(AdminRole.SUPER_ADMIN)) {
            log.warn("Bootstrap super-admin {} has not verified its email address; promoting nobody. "
                    + "Verify the address, then restart.", user.getEmail());
            return;
        }
        if (!alreadyPromoted) {
            user.setSuperAdmin(true);
            user.setAdminRole(AdminRole.SUPER_ADMIN);
            // Any token minted before this carries adm=NONE, so invalidate them
            // rather than leave the user signed in without the authority they
            // were just granted.
            user.setTokenVersion(user.getTokenVersion() + 1);
            userRepository.save(user);
            log.info("Promoted {} (tenant={}) to super admin via bootstrap",
                    user.getEmail(),
                    user.getTenant() != null ? user.getTenant().getSlug() : "<none>");
        }
        ensureGlobalMembership(user);
    }

    /**
     * Cross-tenant admin reach is decided by {@code admin_membership}
     * ({@code TenantAccessor.effectiveRole}), not by the user flags. A
     * super-admin without the global row can administer only their home
     * tenant, and every cross-tenant switch is refused -- which is exactly
     * what production had on 2026-09-11. Idempotent, so it also repairs a user
     * promoted by an earlier version of this class.
     */
    private void ensureGlobalMembership(User user) {
        if (globalMembership.grant(user, null)) {
            log.info("Granted global SUPER_ADMIN membership to bootstrap super admin {}", user.getEmail());
        }
    }
}
