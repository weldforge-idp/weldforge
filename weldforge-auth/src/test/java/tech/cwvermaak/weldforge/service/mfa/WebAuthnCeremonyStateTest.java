package tech.cwvermaak.weldforge.service.mfa;

import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;
import tech.cwvermaak.weldforge.model.User;
import tech.cwvermaak.weldforge.model.WebAuthnCeremony;
import tech.cwvermaak.weldforge.repository.MfaFactorRepository;
import tech.cwvermaak.weldforge.repository.WebAuthnCeremonyRepository;
import tech.cwvermaak.weldforge.service.audit.AuditService;

import java.time.LocalDateTime;
import java.util.Optional;
import java.util.function.Function;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * CONF-3.1 — WebAuthn ceremony state, out of process.
 *
 * <p>Ceremony state used to live in two {@code ConcurrentHashMap}s on whichever
 * instance served the first request. That failed across a rolling update — the
 * deployments run {@code maxUnavailable: 0, maxSurge: 1}, so two pods exist
 * during every deploy — and was the only piece of in-process state preventing a
 * second replica. The maps were also unbounded, so an abandoned ceremony (a
 * user closing the tab at the browser prompt, which is normal) leaked until
 * restart.
 *
 * <p>These tests pin the properties the map gave us for free and which a table
 * does not: single use, and the fact that a challenge token is bound to one
 * user and one ceremony type.
 */
class WebAuthnCeremonyStateTest {

    private WebAuthnService service;
    private WebAuthnCeremonyRepository ceremonyRepository;
    private User alice;
    private User mallory;

    private static final String TOKEN = "challenge-token-abc";
    private static final Function<String, String> IDENTITY = json -> json;

    @BeforeEach
    void setUp() {
        ceremonyRepository = mock(WebAuthnCeremonyRepository.class);
        service = new WebAuthnService(
                null, mock(MfaFactorRepository.class), mock(AuditService.class),
                new SimpleMeterRegistry(), ceremonyRepository);

        alice = new User();
        alice.setId(7L);
        alice.setEmail("alice@leap.test");

        mallory = new User();
        mallory.setId(9L);
        mallory.setEmail("mallory@leap.test");
    }

    private void stored(Long userId, WebAuthnCeremony.Type type, LocalDateTime expiresAt) {
        when(ceremonyRepository.findById(TOKEN)).thenReturn(Optional.of(
                WebAuthnCeremony.builder()
                        .challengeToken(TOKEN)
                        .userId(userId)
                        .ceremonyType(type)
                        .optionsJson("{\"options\":true}")
                        .createdAt(LocalDateTime.now().minusSeconds(10))
                        .expiresAt(expiresAt)
                        .build()));
    }

    private String consume(User user, WebAuthnCeremony.Type expected) {
        return (String) ReflectionTestUtils.invokeMethod(
                service, "consume", TOKEN, user, expected, IDENTITY);
    }

    @Test
    @DisplayName("A ceremony stored by one instance is redeemable by another")
    void ceremony_is_redeemable() {
        stored(7L, WebAuthnCeremony.Type.REGISTRATION, LocalDateTime.now().plusMinutes(4));

        assertThat(consume(alice, WebAuthnCeremony.Type.REGISTRATION))
                .isEqualTo("{\"options\":true}");
    }

    @Test
    @DisplayName("A ceremony is spent by the attempt, not by its success")
    void ceremony_is_single_use() {
        stored(7L, WebAuthnCeremony.Type.REGISTRATION, LocalDateTime.now().plusMinutes(4));

        consume(alice, WebAuthnCeremony.Type.REGISTRATION);

        // Deleted before verification, exactly as the map.remove it replaced
        // did -- otherwise a replayed response could be retried until it worked.
        verify(ceremonyRepository).delete(any(WebAuthnCeremony.class));
    }

    @Test
    @DisplayName("An expired ceremony is refused and dropped on the way past")
    void expired_ceremony_is_refused() {
        stored(7L, WebAuthnCeremony.Type.REGISTRATION, LocalDateTime.now().minusSeconds(1));

        assertThat(consume(alice, WebAuthnCeremony.Type.REGISTRATION)).isNull();
        // Removed here rather than waiting for the hourly prune.
        verify(ceremonyRepository).delete(any(WebAuthnCeremony.class));
    }

    @Test
    @DisplayName("A challenge token cannot be redeemed against a different user")
    void wrong_user_is_refused() {
        stored(7L, WebAuthnCeremony.Type.REGISTRATION, LocalDateTime.now().plusMinutes(4));

        assertThat(consume(mallory, WebAuthnCeremony.Type.REGISTRATION)).isNull();
    }

    @Test
    @DisplayName("An assertion token cannot finish a registration")
    void wrong_ceremony_type_is_refused() {
        // Both types share a table, so nothing else prevents the confusion.
        stored(7L, WebAuthnCeremony.Type.ASSERTION, LocalDateTime.now().plusMinutes(4));

        assertThat(consume(alice, WebAuthnCeremony.Type.REGISTRATION)).isNull();
    }

    @Test
    @DisplayName("An unknown token is refused without touching the database twice")
    void unknown_token_is_refused() {
        when(ceremonyRepository.findById(TOKEN)).thenReturn(Optional.empty());

        assertThat(consume(alice, WebAuthnCeremony.Type.REGISTRATION)).isNull();
        verify(ceremonyRepository, never()).delete(any(WebAuthnCeremony.class));
    }

    @Test
    @DisplayName("A null or blank token is refused before any lookup")
    void blank_token_is_refused() {
        assertThat((String) ReflectionTestUtils.invokeMethod(
                service, "consume", null, alice, WebAuthnCeremony.Type.REGISTRATION, IDENTITY)).isNull();
        assertThat((String) ReflectionTestUtils.invokeMethod(
                service, "consume", "  ", alice, WebAuthnCeremony.Type.REGISTRATION, IDENTITY)).isNull();

        verify(ceremonyRepository, never()).findById(any());
    }
}
