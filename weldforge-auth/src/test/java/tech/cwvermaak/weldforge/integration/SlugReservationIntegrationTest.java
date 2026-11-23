package tech.cwvermaak.weldforge.integration;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import tech.cwvermaak.weldforge.model.payment.OrderStatus;
import tech.cwvermaak.weldforge.model.payment.PendingOrder;
import tech.cwvermaak.weldforge.repository.PendingOrderRepository;

import java.time.LocalDateTime;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * B-PROV-2 — the partial unique index that reserves a slug (V31, redefined in
 * V76). The manual-follow-up path (a gateway-less {@code CREATED} order) must be
 * a SOFT preference that cannot be used to squat a slug, while a card checkout
 * (which carries a gateway and reaches {@code CHECKOUT_STARTED}) keeps its HARD
 * reservation. Only a real Postgres evaluates the partial index, so this has to
 * be an integration test — the BDD suite runs on mocked repositories.
 */
@SpringBootTest
@Testcontainers
@EnabledIfSystemProperty(named = "tests.integration", matches = "true")
@DisplayName("B-PROV-2: manual-path slug reservation is soft, card-path stays hard")
class SlugReservationIntegrationTest {

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
    }

    @BeforeAll
    static void dockerOrSkip() {
        assumeTrue(System.getProperty("tests.integration", "false").equals("true"),
                "Set -Dtests.integration=true to enable Postgres integration tests");
    }

    @Autowired private PendingOrderRepository repository;

    private PendingOrder order(String token, String slug, OrderStatus status) {
        return PendingOrder.builder()
                .orderToken(token)
                .tier("cloud-starter")
                .organisation("Org " + token)
                .contactName("Contact")
                .contactEmail(token + "@example.test")
                .requestedTenantSlug(slug)
                .billingCycle("MONTHLY")
                .currency("USD")
                .amountCents(2900)
                .status(status)
                // selectedGateway deliberately null: this is the manual path
                // unless a test sets a non-CREATED status below.
                .slugReservationExpires(LocalDateTime.now().plusHours(72))
                .build();
    }

    @Test
    @DisplayName("two gateway-less CREATED orders for the same slug both persist (soft)")
    void manualPathIsSoft() {
        repository.saveAndFlush(order("tok-soft-1", "squatme", OrderStatus.CREATED));

        // Before V76 this second save hit the partial unique index and was
        // rejected, which is exactly how one anonymous caller parked a slug.
        // It must now succeed.
        repository.saveAndFlush(order("tok-soft-2", "squatme", OrderStatus.CREATED));

        assertThat(repository.findAll().stream()
                .filter(o -> "squatme".equals(o.getRequestedTenantSlug()))
                .count())
                .as("both manual-path orders for the same slug coexist")
                .isEqualTo(2);
    }

    @Test
    @DisplayName("a CHECKOUT_STARTED order still blocks a second active reservation for the slug (hard)")
    void cardPathStaysHard() {
        repository.saveAndFlush(order("tok-hard-1", "cardslug", OrderStatus.CHECKOUT_STARTED));

        assertThatThrownBy(() ->
                repository.saveAndFlush(order("tok-hard-2", "cardslug", OrderStatus.CHECKOUT_STARTED)))
                .as("an in-flight checkout holds the slug against a second active order")
                .isInstanceOf(DataIntegrityViolationException.class);
    }

    @Test
    @DisplayName("a soft manual order does not block a later card checkout taking the same slug")
    void softDoesNotBlockHard() {
        repository.saveAndFlush(order("tok-mix-1", "mixslug", OrderStatus.CREATED));
        // The card path can still claim the slug the manual order only softly
        // preferred.
        repository.saveAndFlush(order("tok-mix-2", "mixslug", OrderStatus.CHECKOUT_STARTED));

        assertThat(repository.findAll().stream()
                .anyMatch(o -> "mixslug".equals(o.getRequestedTenantSlug())
                        && o.getStatus() == OrderStatus.CHECKOUT_STARTED))
                .isTrue();
    }
}
