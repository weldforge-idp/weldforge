package tech.cwvermaak.intellisso.bdd;

import io.cucumber.java.en.Given;
import io.cucumber.java.en.Then;
import io.cucumber.java.en.When;
import tech.cwvermaak.intellisso.model.AuditEvent;
import tech.cwvermaak.intellisso.model.EmailVerificationToken;
import tech.cwvermaak.intellisso.model.Tenant;
import tech.cwvermaak.intellisso.model.User;
import tech.cwvermaak.intellisso.repository.EmailVerificationTokenRepository;
import tech.cwvermaak.intellisso.repository.TenantRepository;
import tech.cwvermaak.intellisso.repository.UserRepository;
import tech.cwvermaak.intellisso.service.EmailVerificationService;
import tech.cwvermaak.intellisso.service.audit.AuditService;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicLong;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

public class EmailVerificationSteps {

    private final TestWorld world;

    private EmailVerificationTokenRepository tokenRepository;
    private UserRepository userRepository;
    private TenantRepository tenantRepository;
    private AuditService auditService;
    private EmailVerificationService service;

    private Tenant acme;
    private User alice;
    private final List<EmailVerificationToken> tokenStore = new ArrayList<>();
    private final AtomicLong idSeq = new AtomicLong(3000);

    private String lastRawToken;
    private Throwable lastError;

    public EmailVerificationSteps(TestWorld world) {
        this.world = world;
    }

    private void ensureWired() {
        if (service != null) return;

        tokenRepository = mock(EmailVerificationTokenRepository.class);
        userRepository = mock(UserRepository.class);
        tenantRepository = mock(TenantRepository.class);
        auditService = mock(AuditService.class);

        when(tokenRepository.save(any(EmailVerificationToken.class))).thenAnswer(inv -> {
            EmailVerificationToken t = inv.getArgument(0);
            if (t.getId() == null) {
                t.setId(idSeq.getAndIncrement());
                if (t.getCreatedAt() == null) t.setCreatedAt(LocalDateTime.now());
                tokenStore.add(t);
            }
            return t;
        });

        when(tokenRepository.findByTokenHash(anyString())).thenAnswer(inv -> {
            String hash = inv.getArgument(0);
            return tokenStore.stream()
                    .filter(t -> hash.equals(t.getTokenHash()))
                    .findFirst();
        });

        when(userRepository.save(any(User.class))).thenAnswer(inv -> inv.getArgument(0));

        // Capture audit events into the world for assertions.
        doAnswer(inv -> {
            User actor = inv.getArgument(1);
            world.auditLog.add(AuditEvent.builder()
                    .eventType(inv.getArgument(0))
                    .outcome(AuditEvent.Outcome.SUCCESS)
                    .actorUser(actor)
                    .actorEmail(actor != null ? actor.getEmail() : null)
                    .build());
            return null;
        }).when(auditService).recordUserAction(any(), any(), any(), any(), any());

        service = new EmailVerificationService(tokenRepository, userRepository, tenantRepository, auditService);
    }

    @Given("tenant {string} exists for email verification")
    public void tenantExists(String slug) {
        acme = Tenant.builder().id(1L).slug(slug).name(slug).build();
        ensureWired();
    }

    @Given("user {string} exists unverified for email verification")
    public void userExistsUnverified(String email) {
        alice = User.builder()
                .id(idSeq.getAndIncrement())
                .tenant(acme)
                .email(email)
                .username(email)
                .emailVerified(false)
                .active(true)
                .build();
    }

    @When("a verification token is generated for {string}")
    public void generateToken(String email) {
        lastRawToken = service.sendVerification(alice);
    }

    @When("the verification token is submitted")
    public void submitToken() {
        try {
            service.verify(lastRawToken);
            lastError = null;
        } catch (Exception e) {
            lastError = e;
        }
    }

    @When("the verification token is expired")
    public void expireToken() {
        // Find the token in the store and set its expiry to the past.
        String hash = sha256Hex(lastRawToken);
        tokenStore.stream()
                .filter(t -> hash.equals(t.getTokenHash()))
                .forEach(t -> t.setExpiresAt(LocalDateTime.now().minusHours(1)));
    }

    @When("the expired verification token is submitted")
    public void submitExpiredToken() {
        try {
            service.verify(lastRawToken);
            lastError = null;
        } catch (Exception e) {
            lastError = e;
        }
    }

    @Then("the email is marked as verified")
    public void emailVerified() {
        assertThat(lastError).isNull();
        assertThat(alice.isEmailVerified()).isTrue();
    }

    @Then("a {string} audit event is recorded for email verification")
    public void auditEventRecorded(String eventType) {
        assertThat(world.auditLog)
                .extracting(AuditEvent::getEventType)
                .contains(eventType);
    }

    @Then("the verification is rejected")
    public void verificationRejected() {
        assertThat(lastError).isNotNull();
        assertThat(lastError).isInstanceOf(IllegalArgumentException.class);
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
