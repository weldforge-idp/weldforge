package tech.cwvermaak.intellisso.integration;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.transaction.annotation.Transactional;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import tech.cwvermaak.intellisso.config.tenant.TenantContext;
import tech.cwvermaak.intellisso.model.AuthProvider;
import tech.cwvermaak.intellisso.model.EmailVerificationToken;
import tech.cwvermaak.intellisso.model.Tenant;
import tech.cwvermaak.intellisso.model.User;
import tech.cwvermaak.intellisso.repository.EmailVerificationTokenRepository;
import tech.cwvermaak.intellisso.repository.TenantRepository;
import tech.cwvermaak.intellisso.repository.UserRepository;
import tech.cwvermaak.intellisso.service.EmailVerificationService;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.LocalDateTime;
import java.util.HexFormat;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Integration test for the V17 migration (email_verification_tokens table)
 * and the EmailVerificationService. Boots a full Spring context against a
 * Testcontainers Postgres instance and exercises:
 *
 *  - V17 migration applies cleanly
 *  - Full verification flow: create user, send verification, verify token, check emailVerified
 *  - Expired tokens are rejected
 *  - Used tokens cannot be reused
 */
@SpringBootTest
@Testcontainers
@EnabledIfSystemProperty(named = "tests.integration", matches = "true")
@DisplayName("Email verification integration: V17 migration, full flow, expiry, single-use")
class EmailVerificationIntegrationTest {

    @Container
    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:16-alpine")
            .withDatabaseName("intellisso_test")
            .withUsername("test")
            .withPassword("test");

    @DynamicPropertySource
    static void datasource(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url",      POSTGRES::getJdbcUrl);
        registry.add("spring.datasource.username", POSTGRES::getUsername);
        registry.add("spring.datasource.password", POSTGRES::getPassword);
        registry.add("app.crypto.secret", () -> "ci-only-crypto-secret-0123456789abcdef");
        registry.add("spring.jpa.hibernate.ddl-auto", () -> "validate");
    }

    @BeforeAll
    static void dockerOrSkip() {
        assumeTrue(System.getProperty("tests.integration", "false").equals("true"),
                "Set -Dtests.integration=true to enable Postgres integration tests");
    }

    @Autowired private TenantRepository tenantRepository;
    @Autowired private UserRepository userRepository;
    @Autowired private EmailVerificationTokenRepository tokenRepository;
    @Autowired private EmailVerificationService verificationService;

    @BeforeEach
    void setTenantContext() {
        Tenant tenant = tenantRepository.findBySlug("default").orElseThrow();
        TenantContext.set("default", tenant.getId(), true);
    }

    @Test
    @DisplayName("V17 migration creates email_verification_tokens table successfully")
    void v17Migration_appliesCleanly() {
        assertThat(tokenRepository.findAll()).isNotNull();
    }

    @Test
    @Transactional
    @DisplayName("full verification flow: send verification, verify token, emailVerified becomes true")
    void fullVerificationFlow_sendAndVerify() {
        Tenant tenant = tenantRepository.findBySlug("default").orElseThrow();

        User user = userRepository.save(User.builder()
                .tenant(tenant)
                .username("verify-flow-user")
                .email("verify-flow@test.com")
                .provider(AuthProvider.LOCAL)
                .providerId("verify-flow-user")
                .emailVerified(false)
                .active(true)
                .build());

        assertThat(user.isEmailVerified()).isFalse();

        // Send verification — returns the raw token
        String rawToken = verificationService.sendVerification(user);
        assertThat(rawToken).isNotBlank();

        // Verify a token row was persisted
        String tokenHash = sha256Hex(rawToken);
        EmailVerificationToken token = tokenRepository.findByTokenHash(tokenHash).orElseThrow();
        assertThat(token.getUsed()).isFalse();
        assertThat(token.getExpiresAt()).isAfter(LocalDateTime.now());

        // Verify the token
        verificationService.verify(rawToken);

        // User should now be email-verified
        User reloaded = userRepository.findById(user.getId()).orElseThrow();
        assertThat(reloaded.isEmailVerified()).isTrue();

        // Token should be marked as used
        EmailVerificationToken usedToken = tokenRepository.findByTokenHash(tokenHash).orElseThrow();
        assertThat(usedToken.getUsed()).isTrue();
    }

    @Test
    @Transactional
    @DisplayName("expired verification token is rejected")
    void expiredToken_isRejected() {
        Tenant tenant = tenantRepository.findBySlug("default").orElseThrow();

        User user = userRepository.save(User.builder()
                .tenant(tenant)
                .username("expired-verify-user")
                .email("expired-verify@test.com")
                .provider(AuthProvider.LOCAL)
                .providerId("expired-verify-user")
                .emailVerified(false)
                .active(true)
                .build());

        // Create an already-expired token directly in the DB
        String rawToken = "expired-test-token-value";
        String tokenHash = sha256Hex(rawToken);

        tokenRepository.save(EmailVerificationToken.builder()
                .tenant(tenant)
                .user(user)
                .tokenHash(tokenHash)
                .expiresAt(LocalDateTime.now().minusHours(1)) // Already expired
                .build());

        assertThatThrownBy(() -> verificationService.verify(rawToken))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("expired");
    }

    @Test
    @Transactional
    @DisplayName("verification token can only be used once")
    void token_canOnlyBeUsedOnce() {
        Tenant tenant = tenantRepository.findBySlug("default").orElseThrow();

        User user = userRepository.save(User.builder()
                .tenant(tenant)
                .username("single-use-verify-user")
                .email("single-use-verify@test.com")
                .provider(AuthProvider.LOCAL)
                .providerId("single-use-verify-user")
                .emailVerified(false)
                .active(true)
                .build());

        // Send verification
        String rawToken = verificationService.sendVerification(user);

        // First use succeeds
        verificationService.verify(rawToken);

        // Second use fails
        assertThatThrownBy(() -> verificationService.verify(rawToken))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("already used");
    }

    @Test
    @Transactional
    @DisplayName("invalid verification token is rejected")
    void invalidToken_isRejected() {
        assertThatThrownBy(() -> verificationService.verify("totally-bogus-token"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Invalid");
    }

    // ---- Helper (mirrors EmailVerificationService.sha256Hex which is package-private) ----

    private static String sha256Hex(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(input.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hash);
        } catch (Exception e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }
}
