package tech.cwvermaak.weldforge.integration;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.authentication.BadCredentialsException;
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
import tech.cwvermaak.weldforge.service.security.RefreshTokenService;

import java.util.List;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * B-AUTH-6: single-use enforcement must survive concurrency.
 *
 * <p>Rotation used to read the row, test {@code usedAt}/{@code revokedAt} in
 * Java, and write afterwards. Under READ COMMITTED two concurrent rotations
 * both saw the token unused, both passed the test, and the second UPDATE simply
 * overwrote the first — it never re-evaluated a condition that had only ever
 * been evaluated against a stale snapshot. Both callers walked away with a live
 * successor, and reuse detection never ran.
 *
 * <p>That is the case worth testing rather than the sequential one. Reuse
 * detection here revokes the whole family; an attacker racing the legitimate
 * client got tokens <em>and</em> left the family alive, so the victim's session
 * kept working and nothing fired. The containment was strongest against a slow
 * attacker and absent against a fast one.
 *
 * <p>Real Postgres, not a mock: the fix is a conditional UPDATE, and what makes
 * it correct is Postgres re-evaluating the WHERE clause after the row lock is
 * released. An in-memory fake would pass whether or not the fix worked.
 */
@SpringBootTest
@Testcontainers
@EnabledIfSystemProperty(named = "tests.integration", matches = "true")
@DisplayName("Single-use tokens hold under concurrent redemption")
class SingleUseUnderConcurrencyIntegrationTest {

    @Container
    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:16-alpine")
            .withDatabaseName("weldforge_test")
            .withUsername("test")
            .withPassword("test")
            // Every racer holds one connection for its own transaction and a
            // second for the REQUIRES_NEW revoke sweep, so the server needs
            // materially more than the racer count. The container default is
            // ample on paper but this test is the only thing in the suite that
            // asks for them all at once.
            .withCommand("postgres", "-c", "max_connections=200");

    @DynamicPropertySource
    static void datasource(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url",      POSTGRES::getJdbcUrl);
        registry.add("spring.datasource.username", POSTGRES::getUsername);
        registry.add("spring.datasource.password", POSTGRES::getPassword);
        registry.add("app.crypto.secret", () -> "ci-only-crypto-secret-0123456789abcdef");
        registry.add("spring.jpa.hibernate.ddl-auto", () -> "validate");
        registry.add("app.security.rate-limit.enabled", () -> "false");
        // The pool has to be able to hold every racing thread at once, or they
        // serialise on connection acquisition and the race never happens --
        // the test would pass against the unfixed code.
        // Two per racer (the rotation's own transaction plus the REQUIRES_NEW
        // revoke) with headroom. Sized too small, the racers serialise on
        // connection acquisition, the race never happens, and the test passes
        // against the unfixed code -- which is the worst possible outcome for
        // a regression test.
        registry.add("spring.datasource.hikari.maximum-pool-size", () -> "40");
        registry.add("spring.datasource.hikari.connection-timeout", () -> "30000");
    }

    private static final int RACERS = 8;

    @Autowired RefreshTokenService refreshTokens;
    @Autowired RefreshTokenRepository refreshTokenRepository;
    @Autowired TenantRepository tenants;
    @Autowired UserRepository users;
    @Autowired PasswordEncoder passwordEncoder;

    private User newUser() {
        Tenant home = tenants.findBySlug("default").orElseThrow();
        String tag = UUID.randomUUID().toString().substring(0, 8);
        return users.save(User.builder()
                .tenant(home).username("race-" + tag).email("race-" + tag + "@test.example")
                .password(passwordEncoder.encode("correct horse battery staple"))
                .provider(AuthProvider.LOCAL).providerId("race-" + tag).active(true)
                .build());
    }

    /**
     * Fire every task at the same instant. Without the barrier the first thread
     * usually finishes before the last one starts, which is the sequential case
     * already covered elsewhere.
     */
    private <T> List<Future<T>> raceAll(Callable<T> task) throws Exception {
        ExecutorService pool = Executors.newFixedThreadPool(RACERS);
        CyclicBarrier startLine = new CyclicBarrier(RACERS);
        try {
            List<Future<T>> futures = new java.util.ArrayList<>();
            for (int i = 0; i < RACERS; i++) {
                futures.add(pool.submit(() -> {
                    startLine.await(20, TimeUnit.SECONDS);
                    return task.call();
                }));
            }
            pool.shutdown();
            assertThat(pool.awaitTermination(60, TimeUnit.SECONDS))
                    .as("racing tasks should finish well inside the timeout")
                    .isTrue();
            return futures;
        } finally {
            pool.shutdownNow();
        }
    }

    @Test
    @DisplayName("exactly one of eight simultaneous rotations succeeds")
    void concurrent_rotation_yields_one_winner() throws Exception {
        User user = newUser();
        RefreshTokenService.Issued original = refreshTokens.issueNew(user, "10.0.0.1", "junit");
        String raw = original.rawToken();

        AtomicInteger succeeded = new AtomicInteger();
        AtomicInteger refused   = new AtomicInteger();

        List<Future<Boolean>> futures = raceAll(() -> {
            try {
                refreshTokens.rotate(raw, "10.0.0.1", "junit");
                succeeded.incrementAndGet();
                return true;
            } catch (BadCredentialsException expected) {
                // Reuse detected, or the claim was lost. Both are correct
                // refusals; what must not happen is a second success.
                refused.incrementAndGet();
                return false;
            }
        });
        for (Future<Boolean> f : futures) {
            f.get(30, TimeUnit.SECONDS);
        }

        assertThat(succeeded.get())
                .as("exactly one rotation may mint a successor; %d succeeded and %d were refused",
                        succeeded.get(), refused.get())
                .isEqualTo(1);
        assertThat(refused.get()).isEqualTo(RACERS - 1);

        // The presented token must be spent exactly once, whoever won.
        RefreshToken presented = refreshTokenRepository
                .findByTokenHash(RefreshTokenService.hash(raw)).orElseThrow();
        assertThat(presented.getUsedAt())
                .as("the racing token must be marked used")
                .isNotNull();

        // The losers must have been treated as reuse rather than as a retryable
        // hiccup, so the family is revoked. Asserted on the ORIGINAL token
        // specifically, not on every row in the family.
        //
        // Why not every row: the revoke sweep runs in its own transaction
        // (REQUIRES_NEW, so the refusal cannot roll the containment back), and
        // the winner's successor may still be uncommitted when a loser sweeps.
        // The sweep cannot see it, so that successor can survive. That is a
        // real residual gap, not a test artefact -- it is narrow, since the
        // successor is only reachable by whoever won the race, but it means
        // reuse detection contains the family on a best-effort basis when a
        // rotation is in flight. Recorded as a follow-up rather than asserted
        // as correct here; asserting it would make this test flaky and hide the
        // point it exists to prove.
        List<RefreshToken> family = refreshTokenRepository.findByFamilyId(original.row().getFamilyId());
        assertThat(family).isNotEmpty();
        RefreshToken originalRow = family.stream()
                .filter(t -> t.getId().equals(original.row().getId()))
                .findFirst().orElseThrow();
        assertThat(originalRow.getRevokedAt())
                .as("the raced token's family must be revoked — this is the assertion "
                  + "that distinguishes the fix from the bug, since with the race open "
                  + "the losers succeeded and nothing was revoked at all")
                .isNotNull();
    }

    @Test
    @DisplayName("a token already rotated sequentially is still refused")
    void sequential_reuse_is_unaffected() {
        User user = newUser();
        RefreshTokenService.Issued original = refreshTokens.issueNew(user, "10.0.0.2", "junit");

        // First rotation wins.
        RefreshTokenService.Issued successor =
                refreshTokens.rotate(original.rawToken(), "10.0.0.2", "junit");
        assertThat(successor.rawToken()).isNotEqualTo(original.rawToken());

        // Presenting the spent token again is reuse, and kills the family --
        // the behaviour the concurrent case must match, kept here so a
        // regression in either path is attributable.
        try {
            refreshTokens.rotate(original.rawToken(), "10.0.0.2", "junit");
            throw new AssertionError("reusing a rotated token should have been refused");
        } catch (BadCredentialsException expected) {
            // as designed
        }

        assertThat(refreshTokenRepository.findByFamilyId(original.row().getFamilyId()))
                .allSatisfy(t -> assertThat(t.getRevokedAt()).isNotNull());
    }
}
