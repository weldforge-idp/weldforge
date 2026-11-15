package tech.cwvermaak.weldforge.integration;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import tech.cwvermaak.weldforge.model.AdminRole;
import tech.cwvermaak.weldforge.model.AuthProvider;
import tech.cwvermaak.weldforge.model.Tenant;
import tech.cwvermaak.weldforge.model.User;
import tech.cwvermaak.weldforge.repository.TenantRepository;
import tech.cwvermaak.weldforge.repository.UserRepository;
import tech.cwvermaak.weldforge.service.EmailVerificationService;
import tech.cwvermaak.weldforge.service.JwtService;
import tech.cwvermaak.weldforge.service.PasswordResetService;

import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;

/**
 * Security review 2026-11-15: a verification or reset token proves control of
 * the mailbox it was sent to. Both used to act on whatever address the account
 * held when redeemed, so an attacker could register as themselves, keep the
 * verification link, change the account's email to someone else's through
 * {@code PUT /api/auth/me}, then redeem the link -- and their ID tokens said
 * {@code email=<victim>, email_verified=true}. A relying party that links
 * accounts by verified email would hand them the victim's account.
 */
@SpringBootTest
@AutoConfigureMockMvc
@Testcontainers
@EnabledIfSystemProperty(named = "tests.integration", matches = "true")
@DisplayName("Mailed tokens are bound to the address they were sent to")
class EmailChangeTokenBindingIntegrationTest {

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

    @Autowired MockMvc mvc;
    @Autowired TenantRepository tenants;
    @Autowired UserRepository users;
    @Autowired JwtService jwtService;
    @Autowired EmailVerificationService verification;
    @Autowired PasswordResetService passwordReset;
    @Autowired PasswordEncoder encoder;

    private User attacker() {
        Tenant tenant = tenants.findBySlug("default").orElseThrow();
        String tag = UUID.randomUUID().toString().substring(0, 8);
        return users.save(User.builder()
                .tenant(tenant)
                .username("attacker-" + tag)
                .email("attacker-" + tag + "@evil.example")
                .password(encoder.encode("Original-Passw0rd!"))
                .provider(AuthProvider.LOCAL)
                .providerId("attacker-" + tag)
                .emailVerified(false)
                .active(true)
                .adminRole(AdminRole.NONE)
                .build());
    }

    /** Changes the account's email the way the attacker would: through the profile endpoint. */
    private void changeEmailViaProfile(User u, String newEmail) throws Exception {
        String token = jwtService.generateAccessToken(u.getEmail(), u.getTenant().getId(), u.getTenant().getSlug(),
                false, u.getTokenVersion(), null, null, AdminRole.NONE.name(),
                "https://sso.weldforge.org/t/" + u.getTenant().getSlug(), List.of("pwd"), null);
        int status = mvc.perform(put("/api/auth/me")
                        .header("Authorization", "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"" + newEmail + "\"}"))
                .andReturn().getResponse().getStatus();
        assertThat(status).as("email change through /api/auth/me").isEqualTo(200);
        assertThat(users.findById(u.getId()).orElseThrow().getEmail()).isEqualTo(newEmail);
    }

    @Test
    @DisplayName("a verification link for the old address cannot verify the new one")
    void verificationTokenDoesNotFollowEmailChange() throws Exception {
        User u = attacker();
        String keptLink = verification.sendVerification(u);
        String victim = "victim-" + UUID.randomUUID().toString().substring(0, 6) + "@corp.example";

        changeEmailViaProfile(u, victim);

        assertThatThrownBy(() -> verification.verify(keptLink))
                .isInstanceOf(IllegalArgumentException.class);
        User after = users.findById(u.getId()).orElseThrow();
        assertThat(after.getEmail()).isEqualTo(victim);
        assertThat(after.isEmailVerified()).as("victim's address must not be marked verified").isFalse();
    }

    @Test
    @DisplayName("a reset link for the old address cannot reset the password or verify the new one")
    void resetTokenDoesNotFollowEmailChange() throws Exception {
        User u = attacker();
        String keptLink = passwordReset.adminIssueReset(u).rawToken();
        String passwordHashBefore = u.getPassword();
        String victim = "victim-" + UUID.randomUUID().toString().substring(0, 6) + "@corp.example";

        changeEmailViaProfile(u, victim);

        assertThatThrownBy(() -> passwordReset.resetPassword(keptLink, "Brand-New-Passw0rd!"))
                .isInstanceOf(IllegalArgumentException.class);
        User after = users.findById(u.getId()).orElseThrow();
        assertThat(after.isEmailVerified()).isFalse();
        assertThat(after.getPassword()).isEqualTo(passwordHashBefore);
    }

    @Test
    @DisplayName("a link for the address the account still holds works as before")
    void unchangedAddressStillVerifies() {
        User u = attacker();
        String link = verification.sendVerification(u);

        verification.verify(link);

        assertThat(users.findById(u.getId()).orElseThrow().isEmailVerified()).isTrue();
    }

    @Test
    @DisplayName("the address comparison ignores case, like every other email lookup")
    void caseOnlyDifferenceStillVerifies() {
        User u = attacker();
        String link = verification.sendVerification(u);
        u = users.findById(u.getId()).orElseThrow();
        u.setEmail(u.getEmail().toUpperCase());
        users.save(u);

        verification.verify(link);

        assertThat(users.findById(u.getId()).orElseThrow().isEmailVerified()).isTrue();
    }
}
