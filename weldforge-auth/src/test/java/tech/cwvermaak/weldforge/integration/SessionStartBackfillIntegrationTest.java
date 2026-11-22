package tech.cwvermaak.weldforge.integration;

import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;
import java.sql.Timestamp;
import java.time.LocalDateTime;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * WF-2: V74 backfills each existing refresh family's session start from its
 * earliest row, so families that predate the absolute limit are subject to it
 * from their next refresh rather than starting a fresh 30 days at deploy.
 *
 * <p>Flyway alone, no Spring: the point is the state of the data between two
 * migrations, which an application boot cannot stop at.
 */
@Testcontainers
@EnabledIfSystemProperty(named = "tests.integration", matches = "true")
@DisplayName("V74 backfills the session start of existing refresh families")
class SessionStartBackfillIntegrationTest {

    @Container
    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:16-alpine")
            .withDatabaseName("weldforge_test")
            .withUsername("test")
            .withPassword("test");

    private Flyway flyway(String target) {
        return Flyway.configure()
                .dataSource(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword())
                .locations("classpath:db/migration")
                .ignoreMigrationPatterns("*:missing")
                .target(target)
                .load();
    }

    private static void insertToken(Statement s, long userId, long tenantId, UUID family,
                                    LocalDateTime issuedAt) throws Exception {
        s.executeUpdate("insert into refresh_tokens (user_id, tenant_id, family_id, token_hash, issued_at, expires_at) values ("
                + userId + ", " + tenantId + ", '" + family + "', '" + UUID.randomUUID() + "', '"
                + Timestamp.valueOf(issuedAt) + "', '" + Timestamp.valueOf(issuedAt.plusDays(30)) + "')");
    }

    @Test
    @DisplayName("every row in a family gets the family's earliest issue time")
    void backfillsFromTheEarliestRow() throws Exception {
        flyway("72").migrate();

        LocalDateTime t0 = LocalDateTime.of(2026, 9, 1, 8, 0);
        UUID longLived = UUID.randomUUID();
        UUID single = UUID.randomUUID();
        try (Connection c = DriverManager.getConnection(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(),
                POSTGRES.getPassword()); Statement s = c.createStatement()) {
            long tenantId;
            try (ResultSet r = s.executeQuery("select id from tenants where slug = 'default'")) {
                r.next();
                tenantId = r.getLong(1);
            }
            s.executeUpdate("insert into users (tenant_id, username, email, provider, provider_id, active, email_verified,"
                    + " failed_login_attempts, token_version, admin_role, created_at) values ("
                    + tenantId + ", 'backfill', 'backfill@test.example', 'LOCAL', 'backfill', true, true, 0, 0, 'NONE', now())");
            long userId;
            try (ResultSet r = s.executeQuery("select id from users where email = 'backfill@test.example'")) {
                r.next();
                userId = r.getLong(1);
            }
            // A family rotated three times since 1 September, inserted out of order.
            insertToken(s, userId, tenantId, longLived, t0.plusDays(20));
            insertToken(s, userId, tenantId, longLived, t0);
            insertToken(s, userId, tenantId, longLived, t0.plusDays(40));
            insertToken(s, userId, tenantId, single, t0.plusDays(70));
        }

        flyway("74").migrate();

        try (Connection c = DriverManager.getConnection(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(),
                POSTGRES.getPassword()); Statement s = c.createStatement()) {
            try (ResultSet r = s.executeQuery("select distinct session_started_at from refresh_tokens where family_id = '"
                    + longLived + "'")) {
                assertThat(r.next()).isTrue();
                assertThat(r.getTimestamp(1).toLocalDateTime()).isEqualTo(t0);
                assertThat(r.next()).as("one start for the whole family").isFalse();
            }
            try (ResultSet r = s.executeQuery("select session_started_at from refresh_tokens where family_id = '"
                    + single + "'")) {
                r.next();
                assertThat(r.getTimestamp(1).toLocalDateTime()).isEqualTo(t0.plusDays(70));
            }
            try (ResultSet r = s.executeQuery("select is_nullable from information_schema.columns"
                    + " where table_name = 'refresh_tokens' and column_name = 'session_started_at'")) {
                r.next();
                assertThat(r.getString(1)).isEqualTo("NO");
            }
        }
    }
}
