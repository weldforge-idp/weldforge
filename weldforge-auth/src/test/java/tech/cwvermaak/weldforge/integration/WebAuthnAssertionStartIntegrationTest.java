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
import org.springframework.test.web.servlet.MvcResult;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import tech.cwvermaak.weldforge.model.AuthProvider;
import tech.cwvermaak.weldforge.model.MfaFactor;
import tech.cwvermaak.weldforge.model.MfaFactorType;
import tech.cwvermaak.weldforge.model.Tenant;
import tech.cwvermaak.weldforge.model.User;
import tech.cwvermaak.weldforge.model.WebAuthnCeremony;
import tech.cwvermaak.weldforge.repository.MfaFactorRepository;
import tech.cwvermaak.weldforge.repository.TenantRepository;
import tech.cwvermaak.weldforge.repository.UserRepository;
import tech.cwvermaak.weldforge.repository.WebAuthnCeremonyRepository;

import java.util.Base64;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

/**
 * Starting a passkey sign-in, through the real filter chain.
 *
 * <p>2026-09-13, production: every attempt failed with
 * {@code value too long for type character varying(128)}. The ceremony row is
 * keyed by the token the client holds, and for an ASSERTION that token is the
 * MFA challenge JWT -- hundreds of characters. Enrolment never hit it because
 * its key is a short generated string, so passkey sign-in was broken from the
 * day ceremonies moved into the database while enrolment looked healthy.
 */
@SpringBootTest
@AutoConfigureMockMvc
@Testcontainers
@EnabledIfSystemProperty(named = "tests.integration", matches = "true")
@DisplayName("WebAuthn: a sign-in ceremony starts for a real challenge token")
class WebAuthnAssertionStartIntegrationTest {

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

    private static final String PASSWORD = "correct horse battery staple";

    @Autowired MockMvc mvc;
    @Autowired TenantRepository tenants;
    @Autowired UserRepository users;
    @Autowired MfaFactorRepository factors;
    @Autowired WebAuthnCeremonyRepository ceremonies;
    @Autowired PasswordEncoder passwordEncoder;

    /** A user with an enrolled passkey, so login demands a second factor. */
    private User passkeyUser() {
        return passkeyUser(null);
    }

    /**
     * @param duplicateEmail when set, an account with this email already exists
     *                       in another tenant and holds a LOWER id -- the
     *                       production shape, where the global lookup found it
     *                       first.
     */
    private User passkeyUser(String duplicateEmail) {
        Tenant home = tenants.findBySlug("default").orElseThrow();
        String tag = UUID.randomUUID().toString().substring(0, 8);
        String email = duplicateEmail != null ? duplicateEmail : "pk-" + tag + "@test.example";
        User u = users.save(User.builder()
                .tenant(home).username("pk-" + tag).email(email)
                .password(passwordEncoder.encode(PASSWORD))
                .provider(AuthProvider.LOCAL).providerId("pk-" + tag).active(true)
                .build());
        byte[] credId = new byte[32];
        new java.security.SecureRandom().nextBytes(credId);
        Base64.Encoder b64 = Base64.getUrlEncoder().withoutPadding();
        factors.save(MfaFactor.builder()
                .user(u).type(MfaFactorType.WEBAUTHN).label("Windows Hello")
                .credentialId(b64.encodeToString(credId))
                .publicKeyCose(b64.encodeToString(credId))
                .userHandle(b64.encodeToString(String.valueOf(u.getId()).getBytes()))
                .signatureCount(0L).enabled(true).verified(true).uvRequired(true)
                .build());
        return u;
    }

    /** The same person in another tenant, created FIRST so it holds the lower id. */
    private User sameEmailInAnotherTenantFirst(String email) {
        String slug = "other-" + UUID.randomUUID().toString().substring(0, 8);
        Tenant other = tenants.save(Tenant.builder().slug(slug).name(slug).displayName(slug).build());
        return users.save(User.builder()
                .tenant(other).username("dup-" + slug).email(email)
                .password(passwordEncoder.encode(PASSWORD))
                .provider(AuthProvider.LOCAL).providerId("dup-" + slug).active(true)
                .build());
    }

    private String challengeTokenFor(User u) throws Exception {
        MvcResult r = mvc.perform(post("/api/auth/login").header("X-Tenant-Slug", "default")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"identifier\":\"" + u.getEmail() + "\",\"password\":\"" + PASSWORD + "\"}"))
                .andReturn();
        assertThat(r.getResponse().getStatus()).isEqualTo(200);
        String body = r.getResponse().getContentAsString();
        assertThat(body).contains("\"mfaRequired\":true");
        return body.replaceAll(".*\"mfaChallengeToken\":\"([^\"]+)\".*", "$1");
    }

    @Test
    @DisplayName("the challenge token is a JWT, and starting the ceremony accepts it")
    void assertion_starts_for_a_jwt_challenge_token() throws Exception {
        User u = passkeyUser();
        String challengeToken = challengeTokenFor(u);
        // The thing that broke production: three dots and far past 128 chars.
        assertThat(challengeToken.split("\\.")).hasSize(3);
        assertThat(challengeToken.length()).isGreaterThan(128);

        MvcResult r = mvc.perform(post("/api/auth/mfa/webauthn/assertion/start")
                        .header("X-Tenant-Slug", "default")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"challengeToken\":\"" + challengeToken + "\"}"))
                .andReturn();

        assertThat(r.getResponse().getStatus())
                .as("body: %s", r.getResponse().getContentAsString())
                .isEqualTo(200);
        assertThat(r.getResponse().getContentAsString()).contains("publicKey");
    }

    @Test
    @DisplayName("the ceremony is stored under a fixed-length hash, never the raw token")
    void ceremony_row_is_keyed_by_a_hash() throws Exception {
        User u = passkeyUser();
        String challengeToken = challengeTokenFor(u);

        mvc.perform(post("/api/auth/mfa/webauthn/assertion/start")
                        .header("X-Tenant-Slug", "default")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"challengeToken\":\"" + challengeToken + "\"}"))
                .andReturn();

        List<WebAuthnCeremony> rows = ceremonies.findAll().stream()
                .filter(c -> c.getUserId().equals(u.getId())).toList();
        assertThat(rows).hasSize(1);
        String key = rows.get(0).getChallengeToken();
        assertThat(key).hasSize(64).matches("[0-9a-f]{64}");
        assertThat(key).isNotEqualTo(challengeToken);
        assertThat(rows.get(0).getCeremonyType()).isEqualTo(WebAuthnCeremony.Type.ASSERTION);
    }

    @Test
    @DisplayName("starting twice for the same token replaces the ceremony rather than colliding")
    void starting_twice_does_not_conflict() throws Exception {
        User u = passkeyUser();
        String challengeToken = challengeTokenFor(u);
        String body = "{\"challengeToken\":\"" + challengeToken + "\"}";

        for (int i = 0; i < 2; i++) {
            MvcResult r = mvc.perform(post("/api/auth/mfa/webauthn/assertion/start")
                            .header("X-Tenant-Slug", "default")
                            .contentType(MediaType.APPLICATION_JSON).content(body))
                    .andReturn();
            assertThat(r.getResponse().getStatus())
                    .as("attempt %d: %s", i + 1, r.getResponse().getContentAsString())
                    .isEqualTo(200);
        }
    }

    @Test
    @DisplayName("the same email in another tenant does not hijack the ceremony (production, 2026-09-13)")
    void username_is_resolved_within_the_request_tenant() throws Exception {
        // The production shape: the other tenant's row exists first and holds
        // the lower id, so a global username lookup finds IT. The ceremony was
        // then built for the wrong user id and every assertion was refused:
        // "user handle ... does not match username".
        String shared = "dup-" + UUID.randomUUID().toString().substring(0, 8) + "@test.example";
        User elsewhere = sameEmailInAnotherTenantFirst(shared);
        User withPasskey = passkeyUser(shared);
        assertThat(elsewhere.getId()).isLessThan(withPasskey.getId());

        String challengeToken = challengeTokenFor(withPasskey);
        MvcResult r = mvc.perform(post("/api/auth/mfa/webauthn/assertion/start")
                        .header("X-Tenant-Slug", "default")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"challengeToken\":\"" + challengeToken + "\"}"))
                .andReturn();

        assertThat(r.getResponse().getStatus()).isEqualTo(200);
        // The options must offer THIS tenant's credential, not an empty list
        // built from the other tenant's account.
        String credentialId = factors.findByUserIdAndType(withPasskey.getId(), MfaFactorType.WEBAUTHN)
                .get(0).getCredentialId();
        assertThat(r.getResponse().getContentAsString()).contains(credentialId);
    }
}
