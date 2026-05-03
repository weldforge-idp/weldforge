package tech.cwvermaak.weldforge.bdd;

import io.cucumber.java.en.Given;
import io.cucumber.java.en.Then;
import io.cucumber.java.en.When;
import org.springframework.security.authentication.BadCredentialsException;
import tech.cwvermaak.weldforge.model.AuditEvent;
import tech.cwvermaak.weldforge.model.RefreshToken;
import tech.cwvermaak.weldforge.model.Tenant;
import tech.cwvermaak.weldforge.model.User;
import tech.cwvermaak.weldforge.repository.RefreshTokenRepository;
import tech.cwvermaak.weldforge.service.audit.AuditService;
import tech.cwvermaak.weldforge.service.security.RefreshTokenProperties;
import tech.cwvermaak.weldforge.service.security.RefreshTokenService;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicLong;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

public class RefreshTokenRotationSteps {

    private final TestWorld world;

    private RefreshTokenRepository repo;
    private AuditService auditService;
    private RefreshTokenService service;
    private User alice;

    /** Raw → hash → persisted row, mirroring what a real DB would do. */
    private final Map<String, RefreshToken> rowsByHash = new HashMap<>();
    private final Map<UUID, Integer> familyRevokeCounts = new HashMap<>();
    private final AtomicLong idSeq = new AtomicLong(1);

    private String tokenA;
    private String tokenB;

    public RefreshTokenRotationSteps(TestWorld world) {
        this.world = world;
    }

    @Given("alice is logged in and holds refresh token {string}")
    public void aliceIsLoggedIn(String alias) {
        Tenant t = Tenant.builder().id(1L).slug("acme").name("Acme").build();
        alice = User.builder().id(42L).tenant(t).email("alice@acme.test").build();
        world.users.put(alice.getEmail(), alice);

        repo = mock(RefreshTokenRepository.class);
        auditService = mock(AuditService.class);
        RefreshTokenProperties props = new RefreshTokenProperties();
        service = new RefreshTokenService(repo, props, auditService);

        // Mock the repo to use an in-memory map keyed by hash.
        when(repo.save(any(RefreshToken.class))).thenAnswer(inv -> {
            RefreshToken row = inv.getArgument(0);
            if (row.getId() == null) row.setId(idSeq.getAndIncrement());
            rowsByHash.put(row.getTokenHash(), row);
            return row;
        });
        when(repo.findByTokenHash(anyString())).thenAnswer(inv ->
                Optional.ofNullable(rowsByHash.get((String) inv.getArgument(0))));
        when(repo.revokeFamily(any(UUID.class), any(), anyString())).thenAnswer(inv -> {
            UUID family = inv.getArgument(0);
            LocalDateTime now = inv.getArgument(1);
            String reason = inv.getArgument(2);
            int revoked = 0;
            for (RefreshToken r : rowsByHash.values()) {
                if (r.getFamilyId().equals(family) && r.getRevokedAt() == null) {
                    r.setRevokedAt(now);
                    r.setRevokedReason(reason);
                    revoked++;
                }
            }
            familyRevokeCounts.merge(family, revoked, Integer::sum);
            return revoked;
        });

        // Capture audit writes
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
        doAnswer(inv -> {
            var builder = (tech.cwvermaak.weldforge.model.AuditEvent.AuditEventBuilder) inv.getArgument(0);
            world.auditLog.add(builder.build());
            return null;
        }).when(auditService).log(any());

        // Mint the first token
        RefreshTokenService.Issued first = service.issueNew(alice, "1.2.3.4", "ua");
        if ("A".equals(alias)) tokenA = first.rawToken();
    }

    @When("alice exchanges {string} for a new access token")
    public void aliceExchanges(String alias) {
        String raw = "A".equals(alias) ? tokenA : tokenB;
        try {
            RefreshTokenService.Issued issued = service.rotate(raw, "1.2.3.4", "ua");
            if (tokenB == null) tokenB = issued.rawToken();
            world.lastResult = "rotated";
        } catch (BadCredentialsException e) {
            world.lastError = e;
        }
    }

    @Then("the rotation succeeds")
    public void rotationSucceeds() {
        assertThat(world.lastResult).isEqualTo("rotated");
        assertThat(world.lastError).isNull();
    }

    @Then("{string} is marked as used")
    public void tokenIsMarkedUsed(String alias) {
        String raw = "A".equals(alias) ? tokenA : tokenB;
        RefreshToken row = rowsByHash.get(RefreshTokenService.hash(raw));
        assertThat(row).isNotNull();
        assertThat(row.getUsedAt()).isNotNull();
    }

    @Then("a new token {string} is issued in the same family")
    public void newTokenInSameFamily(String alias) {
        assertThat(tokenB).isNotNull();
        RefreshToken a = rowsByHash.get(RefreshTokenService.hash(tokenA));
        RefreshToken b = rowsByHash.get(RefreshTokenService.hash(tokenB));
        assertThat(b).isNotNull();
        assertThat(b.getFamilyId()).isEqualTo(a.getFamilyId());
    }

    @Given("alice has already rotated {string} and received {string}")
    public void aliceHasAlreadyRotated(String aliasA, String aliasB) {
        RefreshTokenService.Issued successor = service.rotate(tokenA, "1.2.3.4", "ua");
        tokenB = successor.rawToken();
        world.lastResult = null;
        world.lastError = null;
    }

    // "the operation is rejected as {string}" is defined once in
    // TenantIsolationSteps and reused here — Cucumber matches by regex, not
    // by class, so we extend the existing step with the bad-credentials
    // branch by asserting separately.
    @Then("the failure is a bad-credentials error")
    public void failureIsBadCreds() {
        assertThat(world.lastError).isInstanceOf(BadCredentialsException.class);
    }

    @Then("every token in the family is revoked")
    public void everyTokenRevoked() {
        RefreshToken a = rowsByHash.get(RefreshTokenService.hash(tokenA));
        RefreshToken b = rowsByHash.get(RefreshTokenService.hash(tokenB));
        assertThat(a.getRevokedAt()).isNotNull();
        assertThat(b.getRevokedAt()).isNotNull();
    }

    @Then("an {string} audit event with outcome DENIED is recorded")
    public void auditDenied(String eventType) {
        assertThat(world.auditLog)
                .anySatisfy(e -> {
                    assertThat(e.getEventType()).isEqualTo(eventType);
                    assertThat(e.getOutcome())
                            .isEqualTo(AuditEvent.Outcome.DENIED);
                });
    }
}
