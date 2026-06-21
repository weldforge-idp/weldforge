package tech.cwvermaak.weldforge.service;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import tech.cwvermaak.weldforge.config.tenant.PublicHostProperties;
import tech.cwvermaak.weldforge.model.TenantSlugHoldback;
import tech.cwvermaak.weldforge.repository.TenantSlugHoldbackRepository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * B-PROV-1: the shared slug validator used by both the admin tenant-create path
 * and the self-service payment funnel. Format, reserved labels, and holdback.
 */
class TenantSlugValidatorTest {

    private PublicHostProperties publicHost;
    private TenantSlugHoldbackRepository holdbackRepo;
    private TenantSlugValidator validator;

    @BeforeEach
    void setUp() {
        publicHost = mock(PublicHostProperties.class);
        holdbackRepo = mock(TenantSlugHoldbackRepository.class);
        validator = new TenantSlugValidator(publicHost, holdbackRepo);
        when(publicHost.getReservedLabels()).thenReturn(List.of("www", "api", "admin"));
        when(publicHost.getSlugHoldbackDays()).thenReturn(90);
        when(holdbackRepo.findFirstBySlugOrderByReleasedAtDesc(anyString())).thenReturn(Optional.empty());
    }

    @Test
    @DisplayName("a clean slug is accepted and normalised (trim + lowercase)")
    void acceptsAndNormalises() {
        assertThat(validator.validate("  Acme-Corp ")).isEqualTo("acme-corp");
    }

    @Test
    @DisplayName("null slug is rejected")
    void rejectsNull() {
        assertThatThrownBy(() -> validator.validate(null))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    @DisplayName("malformed slugs are rejected (too short, leading/trailing dash, spaces, too long)")
    void rejectsMalformed() {
        for (String bad : new String[]{"a", "-bad", "bad-", "has space", "x".repeat(65)}) {
            assertThatThrownBy(() -> validator.validate(bad))
                    .as("slug=%s", bad)
                    .isInstanceOf(IllegalArgumentException.class);
        }
    }

    @Test
    @DisplayName("reserved labels are rejected")
    void rejectsReserved() {
        assertThatThrownBy(() -> validator.validate("admin"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("reserved");
    }

    @Test
    @DisplayName("a slug inside its holdback window is rejected")
    void rejectsHeldBack() {
        when(holdbackRepo.findFirstBySlugOrderByReleasedAtDesc("oldco"))
                .thenReturn(Optional.of(TenantSlugHoldback.builder()
                        .slug("oldco").releasedAt(LocalDateTime.now().minusDays(1)).build()));
        assertThatThrownBy(() -> validator.validate("oldco"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("holdback");
    }

    @Test
    @DisplayName("a slug whose holdback window has expired is accepted")
    void acceptsExpiredHoldback() {
        when(holdbackRepo.findFirstBySlugOrderByReleasedAtDesc("oldco"))
                .thenReturn(Optional.of(TenantSlugHoldback.builder()
                        .slug("oldco").releasedAt(LocalDateTime.now().minusDays(100)).build()));
        assertThat(validator.validate("oldco")).isEqualTo("oldco");
    }
}
