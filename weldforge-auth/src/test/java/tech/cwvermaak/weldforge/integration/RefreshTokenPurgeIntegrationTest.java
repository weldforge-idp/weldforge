package tech.cwvermaak.weldforge.integration;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import tech.cwvermaak.weldforge.model.AuthProvider;
import tech.cwvermaak.weldforge.model.RefreshToken;
import tech.cwvermaak.weldforge.model.Tenant;
import tech.cwvermaak.weldforge.model.User;
import tech.cwvermaak.weldforge.repository.RefreshTokenRepository;
import tech.cwvermaak.weldforge.repository.TenantRepository;
import tech.cwvermaak.weldforge.repository.UserRepository;
import tech.cwvermaak.weldforge.service.security.RefreshTokenPurgeScheduler;

import java.time.LocalDateTime;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * B-PRIV-1: the purge must shrink the table without resurrecting a session.
 *
 * <p>The predicate under test is {@code revokedAt is null}, and it is a
 * security control rather than tidiness. {@code JwtAuthenticationFilter}
 * decides whether an access token's session was terminated by asking whether
 * the family has any revoked row — and reads <em>absence</em> as "not
 * terminated". Delete revoked rows and every logged-out session silently
 * becomes live again for the remaining life of its access token, undoing SAML
 * single-logout and logout-all with no error anywhere.
 *
 * <p>That is the kind of regression a row-count assertion would sail past, so
 * the test asserts on which rows survive, not how many.
 */
@SpringBootTest
@Testcontainers
@EnabledIfSystemProperty(named = "tests.integration", matches = "true")
@DisplayName("Refresh-token purge: expired rows go, revoked rows stay")
class RefreshTokenPurgeIntegrationTest {

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
        registry.add("app.security.refresh-token.purge-after-expiry-days", () -> "7");
    }

    @Autowired RefreshTokenPurgeScheduler purger;
    @Autowired RefreshTokenRepository repository;
    @Autowired TenantRepository tenants;
    @Autowired UserRepository users;
    @Autowired PasswordEncoder passwordEncoder;

    private User newUser() {
        Tenant home = tenants.findBySlug("default").orElseThrow();
        String tag = UUID.randomUUID().toString().substring(0, 8);
        return users.save(User.builder()
                .tenant(home).username("purge-" + tag).email("purge-" + tag + "@test.example")
                .password(passwordEncoder.encode("correct horse battery staple"))
                .provider(AuthProvider.LOCAL).providerId("purge-" + tag).active(true)
                .build());
    }

    private RefreshToken row(User u, LocalDateTime expiresAt, LocalDateTime revokedAt) {
        return repository.save(RefreshToken.builder()
                .user(u)
                .tenant(u.getTenant())
                .familyId(UUID.randomUUID())
                .tokenHash(UUID.randomUUID().toString().replace("-", ""))
                .issuedAt(expiresAt.minusDays(30))
                .expiresAt(expiresAt)
                .revokedAt(revokedAt)
                .revokedReason(revokedAt == null ? null : "test")
                .build());
    }

    @Test
    @DisplayName("long-expired unrevoked rows are deleted; revoked and live rows are not")
    void purge_deletes_only_expired_unrevoked() {
        User u = newUser();
        LocalDateTime now = LocalDateTime.now();

        RefreshToken staleUnrevoked = row(u, now.minusDays(40), null);          // go
        RefreshToken justExpired    = row(u, now.minusDays(1),  null);          // stay: inside the grace window
        RefreshToken live           = row(u, now.plusDays(5),   null);          // stay: still valid
        RefreshToken staleRevoked   = row(u, now.minusDays(40), now.minusDays(39)); // stay: the security case

        purger.purge();

        assertThat(repository.findById(staleUnrevoked.getId()))
                .as("an unrevoked row 40 days past expiry is exactly what this purge exists to remove")
                .isEmpty();
        assertThat(repository.findById(justExpired.getId()))
                .as("the grace window keeps recently-expired rows available for forensics")
                .isPresent();
        assertThat(repository.findById(live.getId()))
                .as("a live token must never be touched")
                .isPresent();

        // The one that matters. JwtAuthenticationFilter reads the ABSENCE of a
        // revoked row as "session not terminated", so deleting this row would
        // make a logged-out session authenticate again.
        assertThat(repository.findById(staleRevoked.getId()))
                .as("a revoked row must survive the purge, however old — deleting it "
                  + "resurrects the session it was revoked to end")
                .isPresent();
        assertThat(repository.existsByFamilyIdAndRevokedAtIsNotNull(staleRevoked.getFamilyId()))
                .as("and the termination check must still see it")
                .isTrue();
    }

    @Test
    @DisplayName("purging an empty window deletes nothing and does not fail")
    void purge_is_a_safe_no_op() {
        User u = newUser();
        RefreshToken live = row(u, LocalDateTime.now().plusDays(10), null);

        purger.purge();

        assertThat(repository.findById(live.getId())).isPresent();
    }
}
