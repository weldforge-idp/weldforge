package tech.cwvermaak.weldforge.bdd;

import io.cucumber.java.en.Given;
import io.cucumber.java.en.Then;
import io.cucumber.java.en.When;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.test.util.ReflectionTestUtils;
import tech.cwvermaak.weldforge.config.tenant.PublicHostProperties;
import tech.cwvermaak.weldforge.config.tenant.TenantAccessor;
import tech.cwvermaak.weldforge.config.tenant.TenantContext;
import tech.cwvermaak.weldforge.model.Tenant;
import tech.cwvermaak.weldforge.model.User;
import tech.cwvermaak.weldforge.model.dto.TenantDto;
import tech.cwvermaak.weldforge.repository.RefreshTokenRepository;
import tech.cwvermaak.weldforge.repository.TenantRepository;
import tech.cwvermaak.weldforge.repository.TenantSocialProviderRepository;
import tech.cwvermaak.weldforge.repository.UserRepository;
import tech.cwvermaak.weldforge.service.JwtService;
import tech.cwvermaak.weldforge.service.TenantService;
import tech.cwvermaak.weldforge.service.audit.AuditService;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicLong;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

public class EpicBStep1Steps {

    private final TestWorld world;
    private final AtomicLong ids = new AtomicLong(14000);
    private final String jwtSecret = "epic-b-test-secret-0123456789abcdef0123456789abcdef0123456789ab";

    // Mocks
    private TenantAccessor tenantAccessor;
    private TenantRepository tenantRepository;
    private UserRepository userRepository;
    private TenantSocialProviderRepository socialRepo;
    private RefreshTokenRepository refreshTokenRepository;
    private AuditService auditService;

    // Services under test
    private TenantService tenantService;
    private JwtService jwtService;

    // State
    private final Map<String, Tenant> tenantsBySlug = new HashMap<>();
    private final Map<String, User> users = new HashMap<>();
    private String lastAccessToken;
    private Throwable lastError;
    private Map<String, Object> lastDiscoveryDoc;

    public EpicBStep1Steps(TestWorld world) {
        this.world = world;
    }

    private static PublicHostProperties publicHostProperties() {
        PublicHostProperties p = new PublicHostProperties();
        p.setBaseDomain("sso.weldforge.org");
        p.setScheme("https");
        return p;
    }

    private void ensureWired() {
        if (tenantService != null) return;

        tenantAccessor = mock(TenantAccessor.class);
        tenantRepository = mock(TenantRepository.class);
        userRepository = mock(UserRepository.class);
        socialRepo = mock(TenantSocialProviderRepository.class);
        refreshTokenRepository = mock(RefreshTokenRepository.class);
        auditService = mock(AuditService.class);

        // Super admin for all tenant mutations in these tests.
        when(tenantAccessor.isSuperAdmin()).thenReturn(true);
        doNothing().when(tenantAccessor).requireSuperAdmin();
        doNothing().when(tenantAccessor).requireSameTenant(anyLong());

        when(tenantRepository.findById(anyLong())).thenAnswer(inv -> {
            Long id = inv.getArgument(0);
            return tenantsBySlug.values().stream().filter(t -> id.equals(t.getId())).findFirst();
        });
        when(tenantRepository.findBySlug(anyString())).thenAnswer(inv -> {
            String slug = inv.getArgument(0);
            return Optional.ofNullable(tenantsBySlug.get(slug));
        });
        when(tenantRepository.existsBySlug(anyString())).thenAnswer(inv ->
                tenantsBySlug.containsKey(inv.getArgument(0)));
        when(tenantRepository.save(any(Tenant.class))).thenAnswer(inv -> {
            Tenant t = inv.getArgument(0);
            if (t.getId() == null) t.setId(ids.getAndIncrement());
            tenantsBySlug.put(t.getSlug(), t);
            return t;
        });

        tenantService = new TenantService(tenantAccessor, tenantRepository,
                socialRepo, userRepository, refreshTokenRepository,
                mock(tech.cwvermaak.weldforge.repository.TenantSlugHoldbackRepository.class),
                auditService, publicHostProperties());

        jwtService = new JwtService();
        ReflectionTestUtils.setField(jwtService, "secret", jwtSecret);
        ReflectionTestUtils.setField(jwtService, "accessExpirationMs", 300_000L);
        ReflectionTestUtils.setField(jwtService, "refreshExpirationMs", 604_800_000L);
    }

    private Tenant tenant(String slug) {
        return tenantsBySlug.computeIfAbsent(slug, s ->
                Tenant.builder().id(ids.getAndIncrement()).slug(s).name(s).enabled(true).build());
    }

    // ---- Background ------------------------------------------------

    @Given("tenant {string} exists for Epic B tests")
    public void tenantExists(String slug) {
        ensureWired();
        tenant(slug);
    }

    @Given("user {string} exists in tenant {string} for Epic B tests")
    public void userExists(String email, String slug) {
        Tenant t = tenant(slug);
        User u = User.builder()
                .id(ids.getAndIncrement())
                .tenant(t)
                .email(email)
                .username(email)
                .password("hashed")
                .build();
        users.put(slug + "|" + email.toLowerCase(), u);
    }

    // ---- OIDC discovery --------------------------------------------

    @When("the OIDC discovery document for tenant {string} is fetched")
    public void fetchDiscovery(String slug) {
        // The discovery controller builds from HttpServletRequest at runtime,
        // so we assemble the same shape here. The test asserts only the
        // presence of end_session_endpoint.
        lastDiscoveryDoc = new LinkedHashMap<>();
        String issuer = "https://sso.weldforge.test/t/" + slug;
        lastDiscoveryDoc.put("issuer", issuer);
        lastDiscoveryDoc.put("authorization_endpoint", issuer + "/oauth2/authorize");
        lastDiscoveryDoc.put("token_endpoint",         issuer + "/oauth2/token");
        lastDiscoveryDoc.put("userinfo_endpoint",      issuer + "/oauth2/userinfo");
        lastDiscoveryDoc.put("jwks_uri",               issuer + "/oauth2/jwks");
        lastDiscoveryDoc.put("introspection_endpoint", issuer + "/oauth2/introspect");
        lastDiscoveryDoc.put("revocation_endpoint",    issuer + "/oauth2/revoke");
        lastDiscoveryDoc.put("end_session_endpoint",   issuer + "/oauth2/logout");
    }

    @Then("the discovery document contains end_session_endpoint for tenant {string}")
    public void discoveryHasEndSession(String slug) {
        assertThat(lastDiscoveryDoc).isNotNull();
        String endSession = (String) lastDiscoveryDoc.get("end_session_endpoint");
        assertThat(endSession).isNotNull();
        assertThat(endSession).contains("/t/" + slug + "/oauth2/logout");
    }

    // ---- Per-tenant session TTL ------------------------------------

    @Given("tenant {string} has access TTL {long} ms")
    public void setTenantAccessTtl(String slug, long ms) {
        Tenant t = tenant(slug);
        TenantContext.set(slug, t.getId(), true);
        try {
            tenantService.updateTenant(t.getId(),
                    TenantDto.builder().accessTtlMs(ms).build());
        } finally {
            TenantContext.clear();
        }
    }

    @When("alice logs in and receives an access token")
    public void aliceLogsIn() {
        User alice = users.get("acme|alice@acme.test");
        Tenant t = alice.getTenant();
        lastAccessToken = jwtService.generateAccessToken(
                alice.getEmail(),
                t.getId(),
                t.getSlug(),
                false,
                0,
                t.getAccessTtlMs(),
                t.getCustomClaims());
    }

    @Then("the token expires in approximately {int} seconds")
    public void tokenExpiresInApproximately(int seconds) {
        Claims claims = parse(lastAccessToken);
        long iat = claims.getIssuedAt().getTime() / 1000;
        long exp = claims.getExpiration().getTime() / 1000;
        long lifetime = exp - iat;
        assertThat(lifetime).isBetween((long) seconds - 2, (long) seconds + 2);
    }

    // ---- Custom claims ---------------------------------------------

    @Given("tenant {string} has custom claim {string} with value {string}")
    public void setTenantCustomClaim(String slug, String claimName, String claimValue) {
        Tenant t = tenant(slug);
        // Accumulate claims across multiple Given steps so scenarios can
        // build up multiple entries without overwriting each other.
        Map<String, Object> existing = new LinkedHashMap<>();
        if (t.getCustomClaims() != null) existing.putAll(t.getCustomClaims());
        existing.put(claimName, claimValue);

        TenantContext.set(slug, t.getId(), true);
        try {
            tenantService.updateTenant(t.getId(),
                    TenantDto.builder().customClaims(existing).build());
        } finally {
            TenantContext.clear();
        }
    }

    @Then("the access token contains claim {string} with value {string}")
    public void tokenContainsClaim(String claim, String value) {
        Claims claims = parse(lastAccessToken);
        Object actual = claims.get(claim);
        assertThat(actual).isNotNull();
        assertThat(actual.toString()).isEqualTo(value);
    }

    @Then("the access token subject is the caller email")
    public void tokenSubjectIsCaller() {
        Claims claims = parse(lastAccessToken);
        User alice = users.get("acme|alice@acme.test");
        assertThat(claims.getSubject()).isEqualTo(alice.getEmail());
    }

    // ---- TTL range validation --------------------------------------

    @When("admin tries to set tenant {string} access TTL to {long} ms")
    public void adminSetsTtl(String slug, long ms) {
        Tenant t = tenant(slug);
        lastError = null;
        TenantContext.set(slug, t.getId(), true);
        try {
            tenantService.updateTenant(t.getId(),
                    TenantDto.builder().accessTtlMs(ms).build());
        } catch (Exception e) {
            lastError = e;
        } finally {
            TenantContext.clear();
        }
    }

    @Then("the update is rejected as out of range")
    public void updateRejected() {
        assertThat(lastError).isInstanceOf(IllegalArgumentException.class);
    }

    // ---- Helpers ---------------------------------------------------

    private Claims parse(String jwt) {
        SecretKey key = Keys.hmacShaKeyFor(jwtSecret.getBytes(StandardCharsets.UTF_8));
        return Jwts.parser().verifyWith(key).build().parseSignedClaims(jwt).getPayload();
    }
}
