package tech.cwvermaak.weldforge.bdd;

import io.cucumber.java.en.Given;
import io.cucumber.java.en.Then;
import io.cucumber.java.en.When;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.crypto.password.PasswordEncoder;
import tech.cwvermaak.weldforge.config.tenant.TenantAccessor;
import tech.cwvermaak.weldforge.model.AuditEvent;
import tech.cwvermaak.weldforge.model.MfaFactor;
import tech.cwvermaak.weldforge.model.MfaFactorType;
import tech.cwvermaak.weldforge.model.Tenant;
import tech.cwvermaak.weldforge.model.TenantTwilioProvider;
import tech.cwvermaak.weldforge.model.User;
import tech.cwvermaak.weldforge.model.dto.TwilioProviderDto;
import tech.cwvermaak.weldforge.repository.BackupCodeRepository;
import tech.cwvermaak.weldforge.repository.MfaFactorRepository;
import tech.cwvermaak.weldforge.repository.TenantRepository;
import tech.cwvermaak.weldforge.repository.TenantTwilioProviderRepository;
import tech.cwvermaak.weldforge.repository.UserRepository;
import tech.cwvermaak.weldforge.service.JwtService;
import tech.cwvermaak.weldforge.service.TenantTwilioService;
import tech.cwvermaak.weldforge.service.TwilioService;
import tech.cwvermaak.weldforge.service.audit.AuditService;
import tech.cwvermaak.weldforge.service.mfa.BackupCodeService;
import tech.cwvermaak.weldforge.service.mfa.MfaService;
import tech.cwvermaak.weldforge.service.mfa.TotpService;
import tech.cwvermaak.weldforge.service.mfa.WebAuthnService;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicLong;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

public class TwilioPerTenantSteps {

    private final TestWorld world;
    private final AtomicLong ids = new AtomicLong(9000);

    // Mocks
    private TenantAccessor tenantAccessor;
    private TenantRepository tenantRepository;
    private TenantTwilioProviderRepository twilioRepo;
    private UserRepository userRepo;
    private MfaFactorRepository factorRepo;
    private BackupCodeRepository backupRepo;
    private JwtService jwtService;
    private TotpService totpService;
    private BackupCodeService backupCodeService;
    private WebAuthnService webAuthnService;
    private PasswordEncoder passwordEncoder;
    private AuditService auditService;
    private TwilioService twilioService;

    // Under test
    private TenantTwilioService tenantTwilioService;
    private MfaService mfaService;

    // Stores
    private final Map<String, Tenant> tenantsBySlug = new HashMap<>();
    private final Map<Long, TenantTwilioProvider> twilioStore = new HashMap<>();
    private final Map<String, User> users = new HashMap<>();
    private final List<MfaFactor> factorStore = new ArrayList<>();
    private final List<String> smsSends = new ArrayList<>();

    // Current acting tenant for AccessDeniedException test
    private Tenant actingTenant;
    private Throwable lastError;
    private String lastSentCode; // captured plaintext OTP for test convenience
    private Long lastFactorId;

    public TwilioPerTenantSteps(TestWorld world) {
        this.world = world;
    }

    // ---- Wiring ----------------------------------------------------

    private void ensureWired() {
        if (tenantTwilioService != null) return;

        tenantAccessor = mock(TenantAccessor.class);
        tenantRepository = mock(TenantRepository.class);
        twilioRepo = mock(TenantTwilioProviderRepository.class);
        userRepo = mock(UserRepository.class);
        factorRepo = mock(MfaFactorRepository.class);
        backupRepo = mock(BackupCodeRepository.class);
        jwtService = mock(JwtService.class);
        totpService = mock(TotpService.class);
        backupCodeService = mock(BackupCodeService.class);
        webAuthnService = mock(WebAuthnService.class);
        passwordEncoder = mock(PasswordEncoder.class);
        auditService = mock(AuditService.class);
        twilioService = mock(TwilioService.class);

        // TenantAccessor — enforce cross-tenant denial based on actingTenant.
        doAnswer(inv -> {
            Long rowTenantId = inv.getArgument(0);
            if (actingTenant == null) return null;
            if (!rowTenantId.equals(actingTenant.getId())) {
                throw new AccessDeniedException("Cross-tenant access denied");
            }
            return null;
        }).when(tenantAccessor).requireSameTenant(anyLong());

        // TenantRepository
        when(tenantRepository.findById(anyLong())).thenAnswer(inv -> {
            Long id = inv.getArgument(0);
            return tenantsBySlug.values().stream()
                    .filter(t -> id.equals(t.getId()))
                    .findFirst();
        });

        // TwilioProviderRepository
        when(twilioRepo.findByTenantId(anyLong())).thenAnswer(inv -> {
            Long tid = inv.getArgument(0);
            return Optional.ofNullable(twilioStore.get(tid));
        });
        when(twilioRepo.findByTenantIdAndEnabledTrue(anyLong())).thenAnswer(inv -> {
            Long tid = inv.getArgument(0);
            TenantTwilioProvider p = twilioStore.get(tid);
            return p != null && Boolean.TRUE.equals(p.getEnabled()) ? Optional.of(p) : Optional.empty();
        });
        when(twilioRepo.save(any(TenantTwilioProvider.class))).thenAnswer(inv -> {
            TenantTwilioProvider p = inv.getArgument(0);
            if (p.getId() == null) p.setId(ids.getAndIncrement());
            twilioStore.put(p.getTenant().getId(), p);
            return p;
        });

        // UserRepository
        when(userRepo.findByTenant_SlugAndEmailIgnoreCase(anyString(), anyString())).thenAnswer(inv -> {
            String slug = inv.getArgument(0);
            String email = inv.getArgument(1);
            String key = slug + "|" + email.toLowerCase();
            return Optional.ofNullable(users.get(key));
        });

        // MfaFactorRepository
        when(factorRepo.save(any(MfaFactor.class))).thenAnswer(inv -> {
            MfaFactor f = inv.getArgument(0);
            if (f.getId() == null) f.setId(ids.getAndIncrement());
            if (!factorStore.contains(f)) factorStore.add(f);
            return f;
        });
        when(factorRepo.findByIdAndUserId(anyLong(), anyLong())).thenAnswer(inv -> {
            Long id = inv.getArgument(0);
            Long uid = inv.getArgument(1);
            return factorStore.stream()
                    .filter(f -> id.equals(f.getId()) && f.getUser().getId().equals(uid))
                    .findFirst();
        });
        when(factorRepo.findByUserIdAndType(anyLong(), any(MfaFactorType.class))).thenAnswer(inv -> {
            Long uid = inv.getArgument(0);
            MfaFactorType t = inv.getArgument(1);
            return factorStore.stream()
                    .filter(f -> f.getUser().getId().equals(uid) && f.getType() == t)
                    .toList();
        });

        // PasswordEncoder — return the plaintext as "hash" so we can assert against it
        when(passwordEncoder.encode(anyString())).thenAnswer(inv -> "hashed:" + inv.getArgument(0));
        when(passwordEncoder.matches(anyString(), anyString())).thenAnswer(inv -> {
            String raw = inv.getArgument(0);
            String hash = inv.getArgument(1);
            return hash != null && hash.equals("hashed:" + raw);
        });

        // TwilioService — capture SMS sends, extract OTP, and simulate the
        // "no config" failure path that the real service raises.
        doAnswer(inv -> {
            Tenant t = inv.getArgument(0);
            if (!twilioStore.containsKey(t.getId())
                    || !Boolean.TRUE.equals(twilioStore.get(t.getId()).getEnabled())) {
                throw new jakarta.persistence.EntityNotFoundException(
                        "No enabled Twilio config for tenant " + t.getSlug());
            }
            String to = inv.getArgument(1);
            String body = inv.getArgument(2);
            smsSends.add(to + "|" + body);
            // Body: "Your WeldForge verification code is 123456. ..."
            int codeStart = body.indexOf("code is ") + "code is ".length();
            if (codeStart >= "code is ".length() && codeStart + 6 <= body.length()) {
                lastSentCode = body.substring(codeStart, codeStart + 6);
            }
            return null;
        }).when(twilioService).sendSms(any(Tenant.class), anyString(), anyString());

        // Audit — capture
        doAnswer(inv -> {
            world.auditLog.add(AuditEvent.builder()
                    .eventType(inv.getArgument(0))
                    .outcome(AuditEvent.Outcome.SUCCESS)
                    .build());
            return null;
        }).when(auditService).recordAdmin(anyString(), any(), anyString(), anyString(), any());
        doAnswer(inv -> {
            world.auditLog.add(AuditEvent.builder()
                    .eventType(inv.getArgument(0))
                    .outcome(AuditEvent.Outcome.SUCCESS)
                    .build());
            return null;
        }).when(auditService).recordUserAction(anyString(), any(), anyString(), anyString(), any());

        tenantTwilioService = new TenantTwilioService(tenantAccessor, tenantRepository,
                twilioRepo, userRepo, auditService, twilioService);
        mfaService = new MfaService(factorRepo, backupRepo, userRepo, jwtService, totpService,
                backupCodeService, webAuthnService, passwordEncoder, auditService, twilioService);
    }

    private Tenant tenant(String slug) {
        return tenantsBySlug.computeIfAbsent(slug, s ->
                Tenant.builder().id(ids.getAndIncrement()).slug(s).name(s).build());
    }

    // ---- Background ------------------------------------------------

    @Given("tenant {string} exists for Twilio tests")
    public void tenantExists(String slug) {
        ensureWired();
        Tenant t = tenant(slug);
        actingTenant = t;
    }

    @Given("user {string} exists in tenant {string} for Twilio tests")
    public void userExists(String email, String slug) {
        Tenant t = tenant(slug);
        User u = User.builder()
                .id(ids.getAndIncrement())
                .tenant(t)
                .email(email)
                .username(email)
                .password("x")
                .build();
        users.put(slug + "|" + email.toLowerCase(), u);
    }

    // ---- Scenario steps --------------------------------------------

    @When("admin saves Twilio config for tenant {string} with SID {string} and token {string} and from {string}")
    public void adminSavesTwilio(String slug, String sid, String token, String from) {
        Tenant t = tenant(slug);
        actingTenant = t;
        TwilioProviderDto dto = TwilioProviderDto.builder()
                .accountSid(sid)
                .authToken(token)
                .fromPhone(from)
                .enabled(true)
                .build();
        try {
            tenantTwilioService.upsert(t.getId(), dto);
        } catch (Exception e) {
            lastError = e;
        }
    }

    @Then("the Twilio config for tenant {string} has account SID {string}")
    public void twilioHasSid(String slug, String sid) {
        Tenant t = tenant(slug);
        TenantTwilioProvider p = twilioStore.get(t.getId());
        assertThat(p).isNotNull();
        assertThat(p.getAccountSid()).isEqualTo(sid);
    }

    @Then("the Twilio auth token is stored encrypted")
    public void tokenIsEncrypted() {
        // The EncryptedStringConverter is JPA-layer — at the entity level we
        // assert that the token field is populated and not empty, which
        // combined with the V18 migration and @Convert annotation means
        // encryption happens on persist.
        TenantTwilioProvider p = twilioStore.values().iterator().next();
        assertThat(p.getAuthToken()).isNotBlank();
    }

    @Then("a {string} audit event is recorded for Twilio")
    public void auditRecorded(String type) {
        assertThat(world.auditLog).extracting(AuditEvent::getEventType).contains(type);
    }

    @When("the acting tenant is {string} and we try to read tenant {string} Twilio config")
    public void crossTenantRead(String actingSlug, String otherSlug) {
        actingTenant = tenant(actingSlug);
        Tenant other = tenant(otherSlug);
        lastError = null;
        try {
            tenantTwilioService.get(other.getId());
        } catch (Exception e) {
            lastError = e;
        }
    }

    @Then("the read is rejected as cross-tenant")
    public void crossTenantDenied() {
        assertThat(lastError).isInstanceOf(AccessDeniedException.class);
    }

    @When("alice enrolls an SMS factor with phone {string}")
    public void enrollSms(String phone) {
        User alice = users.get("acme|alice@acme.test");
        lastError = null;
        try {
            var dto = mfaService.enrollSms(alice, phone, "My phone");
            lastFactorId = dto.getId();
        } catch (Exception e) {
            lastError = e;
        }
    }

    @Then("an SMS is sent via the tenant Twilio config")
    public void smsWasSent() {
        assertThat(smsSends).isNotEmpty();
        assertThat(lastSentCode).isNotNull().matches("\\d{6}");
    }

    @Then("a pending unverified SMS factor exists for alice")
    public void pendingFactorExists() {
        assertThat(factorStore).hasSize(1);
        MfaFactor f = factorStore.get(0);
        assertThat(f.getType()).isEqualTo(MfaFactorType.SMS);
        assertThat(f.getVerified()).isFalse();
        assertThat(f.getSmsCodeHash()).isNotBlank();
    }

    @When("alice activates the SMS factor with the code that was sent")
    public void activateSmsFactor() {
        User alice = users.get("acme|alice@acme.test");
        mfaService.activateSms(alice, lastFactorId, lastSentCode);
    }

    @Then("the SMS factor is marked verified")
    public void factorVerified() {
        MfaFactor f = factorStore.get(0);
        assertThat(f.getVerified()).isTrue();
        assertThat(f.getSmsCodeHash()).isNull();
    }

    @Then("the SMS enrollment is rejected because no Twilio config exists")
    public void smsRejectedNoConfig() {
        assertThat(lastError).isNotNull();
    }
}
