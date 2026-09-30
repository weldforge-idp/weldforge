package tech.cwvermaak.weldforge.service;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import tech.cwvermaak.weldforge.config.tenant.TenantAccessor;
import tech.cwvermaak.weldforge.model.ServiceAccount;
import tech.cwvermaak.weldforge.model.Tenant;
import tech.cwvermaak.weldforge.model.dto.ServiceAccountDto;
import tech.cwvermaak.weldforge.repository.ServiceAccountRepository;
import tech.cwvermaak.weldforge.service.audit.AuditService;

import java.time.LocalDateTime;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.*;

/**
 * Token lifetime through create, update and rotate.
 *
 * <p>The behaviour worth pinning is not that a duration becomes a timestamp —
 * {@link ServiceAccountExpiryTest} covers that — but that the three call
 * sites agree, and that the two states which were previously unreachable now
 * work: making an expiring token permanent again, and rotating one that has
 * already expired.
 */
@DisplayName("Service account lifetime, end to end through the service")
class ServiceAccountLifetimeTest {

    private static final Tenant TENANT =
            Tenant.builder().id(1L).slug("acme").name("Acme").build();

    private TenantAccessor tenantAccessor;
    private ServiceAccountRepository repository;
    private ServiceAccountService service;

    @BeforeEach
    void setUp() {
        tenantAccessor = mock(TenantAccessor.class);
        repository = mock(ServiceAccountRepository.class);
        service = new ServiceAccountService(tenantAccessor, repository, mock(AuditService.class));

        when(tenantAccessor.requireTenant()).thenReturn(TENANT);
        when(tenantAccessor.requireTenantId()).thenReturn(1L);
        when(tenantAccessor.isSuperAdmin()).thenReturn(true);
        when(repository.save(any())).thenAnswer(inv -> inv.getArgument(0));
    }

    private ServiceAccount existing(LocalDateTime expiresAt) {
        ServiceAccount sa = ServiceAccount.builder()
                .id(5L).tenant(TENANT).name("ci").tokenPrefix("wf_svc_aaa")
                .tokenHash("hash").enabled(true).expiresAt(expiresAt)
                .build();
        when(repository.findByIdAndTenantId(anyLong(), anyLong())).thenReturn(Optional.of(sa));
        return sa;
    }

    // ---- create ---------------------------------------------------------

    @Test
    @DisplayName("create with a duration stores an instant, not the duration")
    void create_with_duration() {
        ServiceAccountDto out = service.create(ServiceAccountDto.builder()
                .name("ci").expiresInDays(90).build());

        assertThat(out.getExpiresAt())
                .isAfter(LocalDateTime.now().plusDays(89))
                .isBefore(LocalDateTime.now().plusDays(91));
    }

    @Test
    @DisplayName("create with 0 is indefinite, stated rather than implied")
    void create_indefinite() {
        assertThat(service.create(ServiceAccountDto.builder()
                .name("ci").expiresInDays(0).build()).getExpiresAt()).isNull();
    }

    @Test
    @DisplayName("create with neither field stays indefinite — existing callers unchanged")
    void create_default_is_unchanged_behaviour() {
        assertThat(service.create(ServiceAccountDto.builder().name("ci").build())
                .getExpiresAt()).isNull();
    }

    @Test
    @DisplayName("an absolute expiresAt still works, for callers written before durations")
    void create_absolute_still_supported() {
        LocalDateTime when = LocalDateTime.now().plusDays(3);
        assertThat(service.create(ServiceAccountDto.builder()
                .name("ci").expiresAt(when).build()).getExpiresAt()).isEqualTo(when);
    }

    @Test
    @DisplayName("a duration wins over an absolute value sent in the same request")
    void duration_beats_absolute() {
        ServiceAccountDto out = service.create(ServiceAccountDto.builder()
                .name("ci")
                .expiresAt(LocalDateTime.now().plusYears(5))
                .expiresInDays(1)
                .build());

        assertThat(out.getExpiresAt()).isBefore(LocalDateTime.now().plusDays(2));
    }

    // ---- update ---------------------------------------------------------

    @Test
    @DisplayName("update with 0 makes an expiring token permanent — impossible before")
    void update_can_clear_expiry() {
        ServiceAccount sa = existing(LocalDateTime.now().plusDays(5));

        service.update(5L, ServiceAccountDto.builder().expiresInDays(0).build());

        assertThat(sa.getExpiresAt()).isNull();
    }

    @Test
    @DisplayName("update with neither field leaves the expiry exactly as it was")
    void update_without_duration_is_untouched() {
        LocalDateTime when = LocalDateTime.now().plusDays(5);
        ServiceAccount sa = existing(when);

        service.update(5L, ServiceAccountDto.builder().description("still the CI token").build());

        assertThat(sa.getExpiresAt()).isEqualTo(when);
    }

    @Test
    @DisplayName("update rejects a negative lifetime rather than storing a dead token")
    void update_rejects_negative() {
        existing(null);
        assertThatThrownBy(() -> service.update(5L,
                ServiceAccountDto.builder().expiresInDays(-1).build()))
                .isInstanceOf(IllegalArgumentException.class);
    }

    // ---- rotate ---------------------------------------------------------

    @Test
    @DisplayName("rotating an EXPIRED token without a new lifetime is refused")
    void rotate_expired_without_lifetime_is_refused() {
        existing(LocalDateTime.now().minusDays(1));

        assertThatThrownBy(() -> service.rotate(5L))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("expired")
                // The message must say how to succeed, not only that it failed.
                .hasMessageContaining("expiresInDays");
    }

    @Test
    @DisplayName("rotating an expired token WITH a new lifetime revives it")
    void rotate_expired_with_lifetime_works() {
        ServiceAccount sa = existing(LocalDateTime.now().minusDays(1));

        ServiceAccountDto out = service.rotate(5L,
                ServiceAccountDto.builder().expiresInDays(30).build());

        assertThat(sa.getExpiresAt()).isAfter(LocalDateTime.now());
        assertThat(out.getToken()).isNotBlank();
    }

    @Test
    @DisplayName("rotating a LIVE token without a lifetime keeps its expiry")
    void rotate_live_keeps_expiry() {
        LocalDateTime when = LocalDateTime.now().plusDays(5);
        ServiceAccount sa = existing(when);

        assertThatCode(() -> service.rotate(5L)).doesNotThrowAnyException();
        assertThat(sa.getExpiresAt()).isEqualTo(when);
    }

    @Test
    @DisplayName("rotating an indefinite token is never blocked by the expiry guard")
    void rotate_indefinite_is_fine() {
        ServiceAccount sa = existing(null);

        assertThatCode(() -> service.rotate(5L)).doesNotThrowAnyException();
        assertThat(sa.getExpiresAt()).isNull();
    }

    @Test
    @DisplayName("rotate issues a new secret, and the prefix moves with it")
    void rotate_changes_the_secret() {
        ServiceAccount sa = existing(null);
        String before = sa.getTokenHash();

        ServiceAccountDto out = service.rotate(5L);

        assertThat(sa.getTokenHash()).isNotEqualTo(before);
        assertThat(out.getToken()).isNotBlank();
        assertThat(sa.getTokenPrefix()).isEqualTo(out.getTokenPrefix());
    }
}
