package tech.cwvermaak.weldforge.integration;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.http.MediaType;
import org.springframework.jdbc.datasource.DelegatingDataSource;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import tech.cwvermaak.weldforge.model.AdminRole;
import tech.cwvermaak.weldforge.model.AuthProvider;
import tech.cwvermaak.weldforge.model.User;
import tech.cwvermaak.weldforge.repository.TenantRepository;
import tech.cwvermaak.weldforge.repository.UserRepository;

import javax.sql.DataSource;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.sql.Connection;
import java.sql.SQLException;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

/**
 * Performance test 2026-11-16 (Proboulos WF-17): with open-in-view on and
 * Spring's default DELAYED_ACQUISITION_AND_HOLD, the first query of a request
 * pinned a pooled connection until the request ended. A sign-in held it for
 * the whole BCrypt compare, so ten concurrent sign-ins on one CPU took every
 * connection and unrelated requests failed with 500 after 30 s.
 *
 * <p>The DataSource is wrapped to record which thread holds each borrowed
 * connection, and the probe inside the password compare asks how many the
 * signing-in thread holds. Per thread, because the application's scheduled
 * jobs borrow connections of their own while the test runs.
 */
@SpringBootTest
@AutoConfigureMockMvc
@Testcontainers
@EnabledIfSystemProperty(named = "tests.integration", matches = "true")
@DisplayName("A sign-in holds no database connection while it checks the password")
class LoginConnectionReleaseIntegrationTest {

    @Container
    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:16-alpine")
            .withDatabaseName("weldforge_test")
            .withUsername("test")
            .withPassword("test");

    @DynamicPropertySource
    static void datasource(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url",      POSTGRES::getJdbcUrl);
        registry.add("spring.datasource.username", POSTGRES::getUsername);
        registry.add("spring.datasource.password", POSTGRES::getPassword);
        registry.add("app.crypto.secret", () -> "ci-only-crypto-secret-0123456789abcdef");
        registry.add("spring.jpa.hibernate.ddl-auto", () -> "validate");
        registry.add("app.security.password.breach-check.enabled", () -> "false");
        registry.add("app.security.rate-limit.enabled", () -> "false");
    }

    private static final String PASSWORD = "Correct-Horse-Battery-9";

    /** Connections each thread has borrowed and not yet closed. */
    static final Map<Thread, AtomicInteger> HELD = new ConcurrentHashMap<>();

    /** What the signing-in thread held each time a password was compared. */
    static final List<Integer> HELD_DURING_COMPARE = new CopyOnWriteArrayList<>();

    static final class TrackingDataSource extends DelegatingDataSource {
        TrackingDataSource(DataSource target) {
            super(target);
        }

        @Override
        public Connection getConnection() throws SQLException {
            return track(super.getConnection());
        }

        @Override
        public Connection getConnection(String username, String password) throws SQLException {
            return track(super.getConnection(username, password));
        }

        private static Connection track(Connection real) {
            AtomicInteger mine = HELD.computeIfAbsent(Thread.currentThread(), t -> new AtomicInteger());
            mine.incrementAndGet();
            AtomicBoolean closed = new AtomicBoolean();
            return (Connection) Proxy.newProxyInstance(
                    Connection.class.getClassLoader(), new Class<?>[]{Connection.class},
                    (proxy, method, args) -> {
                        if ("close".equals(method.getName()) && closed.compareAndSet(false, true)) {
                            mine.decrementAndGet();
                        }
                        try {
                            return method.invoke(real, args);
                        } catch (InvocationTargetException e) {
                            throw e.getCause();
                        }
                    });
        }
    }

    @TestConfiguration
    static class ProbeConfig {
        @Bean
        static BeanPostProcessor trackConnectionsPerThread() {
            return new BeanPostProcessor() {
                @Override
                public Object postProcessAfterInitialization(Object bean, String name) {
                    return bean instanceof DataSource ds && !(bean instanceof TrackingDataSource)
                            ? new TrackingDataSource(ds) : bean;
                }
            };
        }

        @Bean
        @Primary
        PasswordEncoder probingPasswordEncoder() {
            PasswordEncoder delegate = new BCryptPasswordEncoder(4);
            return new PasswordEncoder() {
                @Override public String encode(CharSequence raw) { return delegate.encode(raw); }
                @Override public boolean upgradeEncoding(String encoded) { return false; }
                @Override public boolean matches(CharSequence raw, String encoded) {
                    AtomicInteger mine = HELD.get(Thread.currentThread());
                    HELD_DURING_COMPARE.add(mine == null ? 0 : mine.get());
                    return delegate.matches(raw, encoded);
                }
            };
        }
    }

    @Autowired MockMvc mvc;
    @Autowired TenantRepository tenants;
    @Autowired UserRepository users;
    @Autowired PasswordEncoder encoder;

    @Test
    @DisplayName("the signing-in thread holds no connection while the password is compared")
    void connectionIsReleasedDuringPasswordCompare() throws Exception {
        String tag = UUID.randomUUID().toString().substring(0, 8);
        User u = users.save(User.builder()
                .tenant(tenants.findBySlug("default").orElseThrow())
                .username("hasher-" + tag)
                .email("hasher-" + tag + "@test.example")
                .password(encoder.encode(PASSWORD))
                .provider(AuthProvider.LOCAL)
                .providerId("hasher-" + tag)
                .emailVerified(true)
                .active(true)
                .adminRole(AdminRole.NONE)
                .build());
        HELD_DURING_COMPARE.clear();

        int status = mvc.perform(post("/api/auth/login")
                        .header("X-Tenant-Slug", "default")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"identifier\":\"" + u.getEmail() + "\",\"password\":\"" + PASSWORD + "\"}"))
                .andReturn().getResponse().getStatus();

        assertThat(status).as("sign-in").isEqualTo(200);
        assertThat(HELD_DURING_COMPARE)
                .as("the probe ran")
                .isNotEmpty();
        assertThat(HELD_DURING_COMPARE)
                .as("connections the signing-in thread held during the password compare")
                .containsOnly(0);
    }
}
