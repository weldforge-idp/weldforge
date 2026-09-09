package tech.cwvermaak.weldforge.service.mfa;

import com.yubico.webauthn.data.UserVerificationRequirement;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;
import tech.cwvermaak.weldforge.model.MfaFactor;
import tech.cwvermaak.weldforge.model.MfaFactorType;
import tech.cwvermaak.weldforge.model.User;
import tech.cwvermaak.weldforge.repository.MfaFactorRepository;
import tech.cwvermaak.weldforge.service.audit.AuditService;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * CONF-3.2 — demand WebAuthn user verification without locking anyone out.
 *
 * <p>A credential used as a second factor should verify the user, or the factor
 * is only "the key is plugged in". Both ceremonies previously asked for
 * {@code PREFERRED}, which an authenticator is free to ignore.
 *
 * <p>The risk in fixing it is the grandfathering, not the requirement: flipping
 * the assertion ceremony to {@code REQUIRED} globally would lock out every
 * credential enrolled on an authenticator without the capability. These tests
 * pin that boundary — one legacy credential is enough to hold the whole user at
 * {@code PREFERRED}.
 */
class WebAuthnUserVerificationTest {

    private WebAuthnService service;
    private MfaFactorRepository repository;
    private MeterRegistry meterRegistry;
    private User alice;

    @BeforeEach
    void setUp() {
        repository = mock(MfaFactorRepository.class);
        meterRegistry = new SimpleMeterRegistry();
        // RelyingParty is final (Yubico builds it with Lombok @Value), and
        // resolveUserVerification never touches it -- the requirement is decided
        // from the stored factors, before any ceremony starts.
        service = new WebAuthnService(
                null, repository, mock(AuditService.class), meterRegistry,
                mock(tech.cwvermaak.weldforge.repository.WebAuthnCeremonyRepository.class));

        alice = new User();
        alice.setId(7L);
        alice.setEmail("alice@leap.test");
    }

    private MfaFactor factor(MfaFactorType type, boolean uvRequired) {
        return MfaFactor.builder().user(alice).type(type).uvRequired(uvRequired).build();
    }

    private UserVerificationRequirement resolve() {
        return (UserVerificationRequirement) ReflectionTestUtils.invokeMethod(
                service, "resolveUserVerification", alice);
    }

    private double legacyCount() {
        return meterRegistry.counter("mfa.webauthn.legacy_uv").count();
    }

    @Test
    @DisplayName("All credentials enrolled under UV — the ceremony demands it")
    void all_modern_credentials_require_uv() {
        when(repository.findByUserIdAndEnabledTrueAndVerifiedTrue(7L))
                .thenReturn(List.of(factor(MfaFactorType.WEBAUTHN, true),
                                    factor(MfaFactorType.WEBAUTHN, true)));

        assertThat(resolve()).isEqualTo(UserVerificationRequirement.REQUIRED);
        assertThat(legacyCount()).isZero();
    }

    @Test
    @DisplayName("One grandfathered credential holds the whole user at PREFERRED")
    void a_single_legacy_credential_relaxes_the_user() {
        // The user would otherwise be locked out of a key they enrolled in good
        // faith under the old policy. One is enough — this is the case that
        // makes the whole change safe to deploy.
        when(repository.findByUserIdAndEnabledTrueAndVerifiedTrue(7L))
                .thenReturn(List.of(factor(MfaFactorType.WEBAUTHN, true),
                                    factor(MfaFactorType.WEBAUTHN, false)));

        assertThat(resolve()).isEqualTo(UserVerificationRequirement.PREFERRED);
        assertThat(legacyCount())
                .as("metered so the fallback can be retired on evidence, not guesswork")
                .isEqualTo(1.0);
    }

    @Test
    @DisplayName("A TOTP factor is not a WebAuthn credential and must not relax the ceremony")
    void totp_factors_are_ignored() {
        // TOTP rows carry uvRequired=false because the column is meaningless for
        // them. Counting those would hold every TOTP user at PREFERRED forever.
        when(repository.findByUserIdAndEnabledTrueAndVerifiedTrue(7L))
                .thenReturn(List.of(factor(MfaFactorType.WEBAUTHN, true),
                                    factor(MfaFactorType.TOTP, false)));

        assertThat(resolve()).isEqualTo(UserVerificationRequirement.REQUIRED);
        assertThat(legacyCount()).isZero();
    }

    @Test
    @DisplayName("A user with no WebAuthn credentials gets REQUIRED — nothing to grandfather")
    void no_credentials_means_required() {
        when(repository.findByUserIdAndEnabledTrueAndVerifiedTrue(7L)).thenReturn(List.of());

        assertThat(resolve()).isEqualTo(UserVerificationRequirement.REQUIRED);
        assertThat(legacyCount()).isZero();
    }

    @Test
    @DisplayName("Every credential grandfathered still resolves to PREFERRED, counted once")
    void all_legacy_credentials() {
        when(repository.findByUserIdAndEnabledTrueAndVerifiedTrue(7L))
                .thenReturn(List.of(factor(MfaFactorType.WEBAUTHN, false),
                                    factor(MfaFactorType.WEBAUTHN, false)));

        assertThat(resolve()).isEqualTo(UserVerificationRequirement.PREFERRED);
        assertThat(legacyCount()).isEqualTo(1.0);
    }
}
