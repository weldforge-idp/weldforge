package tech.cwvermaak.weldforge.bdd;

import io.cucumber.java.en.And;
import io.cucumber.java.en.Given;
import io.cucumber.java.en.Then;
import io.cucumber.java.en.When;
import tech.cwvermaak.weldforge.config.tenant.TenantContext;
import tech.cwvermaak.weldforge.model.AuditEvent;
import tech.cwvermaak.weldforge.model.AuthProvider;
import tech.cwvermaak.weldforge.model.PasswordResetToken;
import tech.cwvermaak.weldforge.model.Tenant;
import tech.cwvermaak.weldforge.model.User;
import tech.cwvermaak.weldforge.repository.PasswordResetTokenRepository;
import tech.cwvermaak.weldforge.repository.TenantRepository;
import tech.cwvermaak.weldforge.repository.UserRepository;
import tech.cwvermaak.weldforge.service.PasswordResetService;
import tech.cwvermaak.weldforge.service.audit.AuditService;
import tech.cwvermaak.weldforge.service.mail.MailService;
import tech.cwvermaak.weldforge.service.security.PasswordPolicyProperties;
import tech.cwvermaak.weldforge.service.security.PasswordPolicyService;
import tech.cwvermaak.weldforge.service.security.RefreshTokenService;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicLong;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

public class PasswordResetSteps {

    private final TestWorld world;

    private TenantRepository tenantRepository;
    private UserRepository userRepository;
    private PasswordResetTokenRepository resetTokenRepository;
    private AuditService auditService;
    private RefreshTokenService refreshTokenService;
    private MailService mailService;
    private PasswordResetService passwordResetService;

    private Tenant acme;
    private final List<User> userStore = new ArrayList<>();
    private final List<PasswordResetToken> tokenStore = new ArrayList<>();
    private final AtomicLong idSeq = new AtomicLong(3000);

    private String lastRawToken;
    private Throwable lastError;
    private PasswordResetService.IssuedReset adminIssued;

    public PasswordResetSteps(TestWorld world) {
        this.world = world;
    }

    private void ensureWired() {
        if (passwordResetService != null) return;

        tenantRepository = mock(TenantRepository.class);
        userRepository = mock(UserRepository.class);
        resetTokenRepository = mock(PasswordResetTokenRepository.class);
        auditService = mock(AuditService.class);
        refreshTokenService = mock(RefreshTokenService.class);
        mailService = mock(MailService.class);

        PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

        PasswordPolicyProperties props = new PasswordPolicyProperties();
        props.setMinLength(8);
        props.setMaxLength(72);
        props.setRequireUppercase(true);
        props.setRequireLowercase(true);
        props.setRequireDigit(true);
        props.setRequireSymbol(true);
        PasswordPolicyService passwordPolicyService = new PasswordPolicyService(props);

        when(tenantRepository.findBySlug(anyString())).thenAnswer(inv -> {
            String slug = inv.getArgument(0);
            if (acme != null && acme.getSlug().equals(slug)) return Optional.of(acme);
            return Optional.empty();
        });

        when(userRepository.findByTenantIdAndEmailIgnoreCase(anyLong(), anyString())).thenAnswer(inv -> {
            Long tid = inv.getArgument(0);
            String email = inv.getArgument(1);
            return userStore.stream()
                    .filter(u -> u.getTenant().getId().equals(tid)
                            && email.equalsIgnoreCase(u.getEmail()))
                    .findFirst();
        });

        when(userRepository.save(any(User.class))).thenAnswer(inv -> inv.getArgument(0));

        when(resetTokenRepository.save(any(PasswordResetToken.class))).thenAnswer(inv -> {
            PasswordResetToken t = inv.getArgument(0);
            if (t.getId() == null) {
                t.setId(idSeq.getAndIncrement());
                tokenStore.add(t);
            }
            return t;
        });

        doAnswer(inv -> {
            Long userId = inv.getArgument(0);
            tokenStore.removeIf(t -> t.getUser().getId().equals(userId) && !t.isUsed());
            return null;
        }).when(resetTokenRepository).deleteByUserIdAndUsedFalse(anyLong());

        when(resetTokenRepository.findByTokenHash(anyString())).thenAnswer(inv -> {
            String hash = inv.getArgument(0);
            return tokenStore.stream()
                    .filter(t -> hash.equals(t.getTokenHash()))
                    .findFirst();
        });

        // Capture audit events into the world for assertions across step classes.
        doAnswer(inv -> {
            AuditEvent.AuditEventBuilder builder = inv.getArgument(0);
            world.auditLog.add(builder.build());
            return null;
        }).when(auditService).log(any());

        doAnswer(inv -> {
            String eventType = inv.getArgument(0);
            User actor = inv.getArgument(1);
            world.auditLog.add(AuditEvent.builder()
                    .eventType(eventType)
                    .outcome(AuditEvent.Outcome.SUCCESS)
                    .tenant(actor != null ? actor.getTenant() : null)
                    .actorUser(actor)
                    .actorEmail(actor != null ? actor.getEmail() : null)
                    .build());
            return null;
        }).when(auditService).recordUserAction(anyString(), any(User.class), anyString(), anyString(), any());

        passwordResetService = new PasswordResetService(
                userRepository,
                tenantRepository,
                resetTokenRepository,
                passwordEncoder,
                passwordPolicyService,
                auditService,
                refreshTokenService,
                mailService
        );
    }

    @Given("tenant {string} exists for password reset")
    public void tenantExistsForPasswordReset(String slug) {
        acme = Tenant.builder().id(1L).slug(slug).name(slug).build();
        TenantContext.set(slug);
        ensureWired();
    }

    @Given("user {string} exists with password {string} for password reset")
    public void userExistsWithPassword(String email, String password) {
        PasswordEncoder encoder = new BCryptPasswordEncoder();
        User user = User.builder()
                .id(idSeq.getAndIncrement())
                .tenant(acme)
                .email(email)
                .username(email)
                .password(encoder.encode(password))
                .provider(AuthProvider.LOCAL)
                .providerId("local")
                .active(true)
                .tokenVersion(0)
                .build();
        userStore.add(user);
    }

    @When("a password reset is requested for {string}")
    public void passwordResetRequested(String email) {
        lastError = null;
        lastRawToken = null;
        try {
            // Intercept the generated token by spying on what gets saved.
            int sizeBefore = tokenStore.size();
            passwordResetService.requestReset(email);
            if (tokenStore.size() > sizeBefore) {
                // Recover the raw token: hash the last saved token and reverse-lookup.
                // Instead, we capture it from the saved tokenHash by brute force — but
                // that's not feasible. Instead, we'll call generateToken + sha256Hex
                // directly as the service does, but we need the raw value.
                // Better approach: extract the raw token from the log output.
                // Simplest for testing: generate a token ourselves, then do the reset
                // using the token hash stored.
                //
                // Actually, we can't easily intercept. Let's use a different approach:
                // call the service and then find what was stored, then craft a raw
                // token that matches. But SHA-256 is one-way.
                //
                // The proper test approach: generate a token, hash it, store it, then
                // use the raw token for reset. Let's do this by directly creating
                // the token in the test.
                lastRawToken = null; // Will handle in a different way - see below.
            }
        } catch (Exception e) {
            lastError = e;
        }
    }

    @Then("a reset token is generated")
    public void resetTokenGenerated() {
        assertThat(lastError).isNull();
        assertThat(tokenStore).isNotEmpty();
    }

    @When("the reset token is used with new password {string}")
    public void resetTokenUsed(String newPassword) {
        lastError = null;
        // We need the raw token. Since we can't intercept it from the service,
        // generate a new one, hash it, and update the stored token's hash.
        String rawToken = generateToken();
        String hash = sha256Hex(rawToken);
        PasswordResetToken stored = tokenStore.get(tokenStore.size() - 1);
        stored.setTokenHash(hash);
        lastRawToken = rawToken;

        try {
            passwordResetService.resetPassword(rawToken, newPassword);
        } catch (Exception e) {
            lastError = e;
        }
    }

    @Then("the password is changed successfully")
    public void passwordChangedSuccessfully() {
        assertThat(lastError).isNull();
        PasswordResetToken stored = tokenStore.get(tokenStore.size() - 1);
        assertThat(stored.isUsed()).isTrue();
    }

    @And("a {string} audit event is recorded for password reset")
    public void auditEventRecorded(String eventType) {
        assertThat(world.auditLog)
                .extracting(AuditEvent::getEventType)
                .contains(eventType);
    }

    @Then("every active session for the user is terminated")
    public void everySessionTerminated() {
        assertThat(lastError).isNull();
        // The reset must revoke the refresh-token side; token_version alone
        // only kills access tokens and would leave a thief's session alive.
        verify(refreshTokenService).revokeAllForUser(any(User.class), eq("password_reset"));
    }

    @And("the token is expired")
    public void tokenIsExpired() {
        PasswordResetToken stored = tokenStore.get(tokenStore.size() - 1);
        stored.setExpiresAt(LocalDateTime.now().minusMinutes(1));
    }

    @When("the expired token is used with new password {string}")
    public void expiredTokenUsed(String newPassword) {
        lastError = null;
        // Replace the hash with a known raw token so we can pass it to resetPassword.
        String rawToken = generateToken();
        String hash = sha256Hex(rawToken);
        PasswordResetToken stored = tokenStore.get(tokenStore.size() - 1);
        stored.setTokenHash(hash);

        try {
            passwordResetService.resetPassword(rawToken, newPassword);
        } catch (Exception e) {
            lastError = e;
        }
    }

    @Then("the reset is rejected")
    public void resetIsRejected() {
        assertThat(lastError).isNotNull();
        assertThat(lastError).isInstanceOf(IllegalArgumentException.class);
    }

    @Then("no error is returned")
    public void noErrorReturned() {
        assertThat(lastError).isNull();
    }

    @When("an admin issues a password reset for {string}")
    public void adminIssuesReset(String email) {
        lastError = null;
        adminIssued = null;
        User user = userStore.stream()
                .filter(u -> email.equalsIgnoreCase(u.getEmail()))
                .findFirst()
                .orElseThrow(() -> new AssertionError("no such user: " + email));
        try {
            adminIssued = passwordResetService.adminIssueReset(user);
        } catch (Exception e) {
            lastError = e;
        }
    }

    @Then("a reset token is returned to the admin")
    public void resetTokenReturnedToAdmin() {
        assertThat(lastError).isNull();
        assertThat(adminIssued).isNotNull();
        assertThat(adminIssued.rawToken()).isNotBlank();
    }

    // ---- test helpers (mirror PasswordResetService internals) --------

    private static String generateToken() {
        byte[] bytes = new byte[32];
        new SecureRandom().nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private static String sha256Hex(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(input.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }
}
