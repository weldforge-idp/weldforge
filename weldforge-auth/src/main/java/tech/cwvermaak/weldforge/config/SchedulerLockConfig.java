package tech.cwvermaak.weldforge.config;

import net.javacrumbs.shedlock.core.LockProvider;
import net.javacrumbs.shedlock.provider.jdbctemplate.JdbcTemplateLockProvider;
import net.javacrumbs.shedlock.spring.annotation.EnableSchedulerLock;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcTemplate;

import javax.sql.DataSource;

/**
 * Makes the scheduled jobs safe to run with more than one instance.
 *
 * <p>Spring runs every {@code @Scheduled} method on every instance. At one
 * replica that costs nothing and is invisible; at two it means two provisioning
 * retries for the same paid order, two deliveries of the same webhook, and two
 * concurrent signing-key rotations. That made horizontal scaling unsafe
 * regardless of how much hardware was available — this class is what removes
 * that constraint, together with the {@code @SchedulerLock} annotations on the
 * jobs themselves.
 *
 * <p><strong>Database-backed, not Redis-backed, on purpose.</strong> Every
 * instance already shares one Postgres, so scaling out does not also mean
 * standing up and operating another stateful dependency. The lock table is
 * created by {@code V58__shedlock.sql}.
 *
 * <p>The default lock ceiling is deliberately short. A lock is a lease: if an
 * instance dies mid-job, the work stays blocked until the lease expires, so a
 * long default trades a rare duplicate for a common stall. Individual jobs
 * override it where their work legitimately takes longer.
 *
 * @see tech.cwvermaak.weldforge.service.payment.ProvisioningRetryScheduler
 */
@Configuration
@EnableSchedulerLock(defaultLockAtMostFor = "PT5M")
public class SchedulerLockConfig {

    @Bean
    public LockProvider lockProvider(DataSource dataSource) {
        return new JdbcTemplateLockProvider(
                JdbcTemplateLockProvider.Configuration.builder()
                        .withJdbcTemplate(new JdbcTemplate(dataSource))
                        // Postgres' own clock, not each pod's. Instances whose
                        // clocks drift apart would otherwise disagree about
                        // when a lease expired, which is the one thing this
                        // table exists to be authoritative about.
                        .usingDbTime()
                        .build());
    }
}
