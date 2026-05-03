package tech.cwvermaak.weldforge.integration;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.transaction.annotation.Transactional;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import tech.cwvermaak.weldforge.config.tenant.TenantContext;
import tech.cwvermaak.weldforge.model.AuthProvider;
import tech.cwvermaak.weldforge.model.PasswordResetToken;
import tech.cwvermaak.weldforge.model.Tenant;
import tech.cwvermaak.weldforge.model.User;
import tech.cwvermaak.weldforge.repository.PasswordResetTokenRepository;
import tech.cwvermaak.weldforge.repository.TenantRepository;
import tech.cwvermaak.weldforge.repository.UserRepository;
import tech.cwvermaak.weldforge.service.PasswordResetService;

import java.time.LocalDateTime;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Integration test for the V16 migration (password_reset_tokens table)
 * and the PasswordResetService. Boots a full Spring context against a
 * Testcontainers Postgres instance and exercises:
 *
 *  - V16 migration applies cleanly
 *  - Full reset flow: create user, request reset, use token, verify password changed
 *  - Expired tokens are rejected
 *  - Used tokens cannot be reused
 */
@SpringBootTest
@Testcontainers
@EnabledIfSystemProperty(named = "tests.integration", matches = "true")
@DisplayName("Password reset integration: V16 migration, full flow, expiry, single-use")
class PasswordResetIntegrationTest {

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
    @Autowired private PasswordResetTokenRepository resetTokenRepository;
    @Autowired private PasswordResetService passwordResetService;
    @Autowired private PasswordEncoder passwordEncoder;

    @BeforeEach
    void setTenantContext() {
        Tenant tenant = tenantRepository.findBySlug("default").orElseThrow();
        TenantContext.set("default", tenant.getId(), true);
    }

    @Test
    @DisplayName("V16 migration creates password_reset_tokens table successfully")
    void v16Migration_appliesCleanly() {
        assertThat(resetTokenRepository.findAll()).isNotNull();
    }

    @Test
    @Transactional
    @DisplayName("full password reset flow: request, use token, verify password changed")
    void fullResetFlow_requestAndUseToken() {
        Tenant tenant = tenantRepository.findBySlug("default").orElseThrow();

        // Create a user with a known password
        String originalPassword = "Original1!";
        User user = userRepository.save(User.builder()
                .tenant(tenant)
                .username("reset-flow-user")
                .email("reset-flow@test.com")
                .password(passwordEncoder.encode(originalPassword))
                .provider(AuthProvider.LOCAL)
                .providerId("reset-flow-user")
                .active(true)
                .build());

        int originalTokenVersion = user.getTokenVersion();

        // Generate a token manually (the service logs it; in tests we create directly)
        String rawToken = PasswordResetService.generateToken();
        String tokenHash = PasswordResetService.sha256Hex(rawToken);

        PasswordResetToken resetToken = resetTokenRepository.save(PasswordResetToken.builder()
                .tenant(tenant)
                .user(user)
                .tokenHash(tokenHash)
                .expiresAt(LocalDateTime.now().plusHours(1))
                .build());

        assertThat(resetToken.getId()).isNotNull();
        assertThat(resetToken.isUsed()).isFalse();

        // Use the token to reset the password
        String newPassword = "NewPassword1!";
        passwordResetService.resetPassword(rawToken, newPassword);

        // Verify password was changed
        User reloaded = userRepository.findById(user.getId()).orElseThrow();
        assertThat(passwordEncoder.matches(newPassword, reloaded.getPassword())).isTrue();
        assertThat(passwordEncoder.matches(originalPassword, reloaded.getPassword())).isFalse();

        // Verify token version was bumped (invalidating existing sessions)
        assertThat(reloaded.getTokenVersion()).isGreaterThan(originalTokenVersion);

        // Verify token is marked as used
        PasswordResetToken usedToken = resetTokenRepository.findByTokenHash(tokenHash).orElseThrow();
        assertThat(usedToken.isUsed()).isTrue();
    }

    @Test
    @Transactional
    @DisplayName("expired token is rejected")
    void expiredToken_isRejected() {
        Tenant tenant = tenantRepository.findBySlug("default").orElseThrow();

        User user = userRepository.save(User.builder()
                .tenant(tenant)
                .username("expired-token-user")
                .email("expired-token@test.com")
                .password(passwordEncoder.encode("Original1!"))
                .provider(AuthProvider.LOCAL)
                .providerId("expired-token-user")
                .active(true)
                .build());

        // Create an already-expired token
        String rawToken = PasswordResetService.generateToken();
        String tokenHash = PasswordResetService.sha256Hex(rawToken);

        resetTokenRepository.save(PasswordResetToken.builder()
                .tenant(tenant)
                .user(user)
                .tokenHash(tokenHash)
                .expiresAt(LocalDateTime.now().minusHours(1)) // Already expired
                .build());

        assertThatThrownBy(() -> passwordResetService.resetPassword(rawToken, "NewPassword1!"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Invalid or expired");
    }

    @Test
    @Transactional
    @DisplayName("token can only be used once")
    void token_canOnlyBeUsedOnce() {
        Tenant tenant = tenantRepository.findBySlug("default").orElseThrow();

        User user = userRepository.save(User.builder()
                .tenant(tenant)
                .username("single-use-user")
                .email("single-use@test.com")
                .password(passwordEncoder.encode("Original1!"))
                .provider(AuthProvider.LOCAL)
                .providerId("single-use-user")
                .active(true)
                .build());

        String rawToken = PasswordResetService.generateToken();
        String tokenHash = PasswordResetService.sha256Hex(rawToken);

        resetTokenRepository.save(PasswordResetToken.builder()
                .tenant(tenant)
                .user(user)
                .tokenHash(tokenHash)
                .expiresAt(LocalDateTime.now().plusHours(1))
                .build());

        // First use succeeds
        passwordResetService.resetPassword(rawToken, "NewPassword1!");

        // Second use fails
        assertThatThrownBy(() -> passwordResetService.resetPassword(rawToken, "AnotherPassword1!"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Invalid or expired");
    }

    @Test
    @Transactional
    @DisplayName("invalid token is rejected")
    void invalidToken_isRejected() {
        assertThatThrownBy(() -> passwordResetService.resetPassword("totally-bogus-token", "NewPassword1!"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Invalid or expired");
    }
}
