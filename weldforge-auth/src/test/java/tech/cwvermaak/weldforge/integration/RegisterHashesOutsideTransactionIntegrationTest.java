package tech.cwvermaak.weldforge.integration;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.SpyBean;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import tech.cwvermaak.weldforge.model.Tenant;
import tech.cwvermaak.weldforge.repository.TenantRepository;
import tech.cwvermaak.weldforge.repository.UserRepository;

import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * WF-19 — registration must not hold a database connection while it hashes the
 * password. The whole method used to be one transaction, so the BCrypt hash ran
 * with a pooled connection pinned for its full ~hundreds of milliseconds, and
 * four concurrent sign-ups starved the pool (p95 12 s). This proves the
 * contract directly: when the password is hashed, no transaction is active, so
 * no connection is being held across the hash. Same guarantee login already
 * has (WF-17).
 */
@SpringBootTest
@AutoConfigureMockMvc
@Testcontainers
@EnabledIfSystemProperty(named = "tests.integration", matches = "true")
@DisplayName("Registration hashes the password outside any transaction")
class RegisterHashesOutsideTransactionIntegrationTest {

    @Container
    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:18.1-alpine")
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
    @SpyBean PasswordEncoder passwordEncoder;

    private Tenant tenant;
    private String tag;

    @BeforeEach
    void seed() {
        tag = UUID.randomUUID().toString().substring(0, 8);
        tenant = tenants.saveAndFlush(Tenant.builder()
                .slug("reg-" + tag).name("reg-" + tag).displayName("reg-" + tag).build());
    }

    @Test
    @DisplayName("the BCrypt hash runs with no active transaction, and registration still works")
    void hashRunsWithoutActiveTransaction() throws Exception {
        AtomicReference<Boolean> transactionActiveDuringEncode = new AtomicReference<>();
        doAnswer(invocation -> {
            transactionActiveDuringEncode.set(TransactionSynchronizationManager.isActualTransactionActive());
            return invocation.callRealMethod();
        }).when(passwordEncoder).encode(any());

        String email = "signup-" + tag + "@test.example";
        mvc.perform(post("/api/auth/register")
                        .header("X-Tenant-Slug", tenant.getSlug())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"name\":\"New Signup\",\"email\":\"" + email
                                 + "\",\"password\":\"" + PASSWORD + "\"}"))
                .andExpect(status().is2xxSuccessful());

        assertThat(transactionActiveDuringEncode.get())
                .as("the password hash must not run inside a transaction holding a connection")
                .isFalse();
        assertThat(users.findByTenant_SlugAndEmailIgnoreCase(tenant.getSlug(), email)).isPresent();
    }
}
