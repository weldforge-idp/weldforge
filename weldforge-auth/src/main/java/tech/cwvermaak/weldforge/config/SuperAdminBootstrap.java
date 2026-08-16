package tech.cwvermaak.weldforge.config;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;
import tech.cwvermaak.weldforge.model.AdminRole;
import tech.cwvermaak.weldforge.model.User;
import tech.cwvermaak.weldforge.repository.UserRepository;

/**
 * One-time bootstrap: if {@code APP_ADMIN_BOOTSTRAP_SUPER_ADMIN_EMAIL} is set
 * and a user with that email exists in any tenant, promote them to super
 * admin. This exists so a freshly-installed system can be bootstrapped without
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

    private final UserRepository userRepository;

    @Override
    public void run(ApplicationArguments args) {
        if (bootstrapEmail == null || bootstrapEmail.isBlank()) return;

        userRepository.findFirstByEmailIgnoreCase(bootstrapEmail.trim())
                .ifPresentOrElse(
                        this::promote,
                        () -> log.warn("Bootstrap super-admin email {} does not match any existing user — "
                                + "create the user first, then restart.", bootstrapEmail));
    }

    private void promote(User user) {
        if (user.isSuperAdmin() && user.getAdminRole() == AdminRole.SUPER_ADMIN) return;
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
}
