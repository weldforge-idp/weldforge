package tech.cwvermaak.weldforge.config;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;
import tech.cwvermaak.weldforge.model.User;
import tech.cwvermaak.weldforge.repository.UserRepository;

/**
 * One-time bootstrap: if {@code APP_BOOTSTRAP_SUPER_ADMIN_EMAIL} is set and a
 * user with that email exists in any tenant, mark them as super admin. This
 * exists so a freshly-installed system can be bootstrapped without a manual
 * UPDATE against the database.
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
        if (user.isSuperAdmin()) return;
        user.setSuperAdmin(true);
        userRepository.save(user);
        log.info("Promoted {} (tenant={}) to super admin via bootstrap",
                user.getEmail(),
                user.getTenant() != null ? user.getTenant().getSlug() : "<none>");
    }
}
