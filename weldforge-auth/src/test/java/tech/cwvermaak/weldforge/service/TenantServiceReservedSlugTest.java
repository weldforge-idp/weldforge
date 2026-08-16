package tech.cwvermaak.weldforge.service;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import tech.cwvermaak.weldforge.config.tenant.PublicHostProperties;
import tech.cwvermaak.weldforge.config.tenant.TenantAccessor;
import tech.cwvermaak.weldforge.model.Tenant;
import tech.cwvermaak.weldforge.model.dto.TenantDto;
import tech.cwvermaak.weldforge.repository.RefreshTokenRepository;
import tech.cwvermaak.weldforge.repository.TenantRepository;
import tech.cwvermaak.weldforge.repository.TenantSlugHoldbackRepository;
import tech.cwvermaak.weldforge.repository.TenantSocialProviderRepository;
import tech.cwvermaak.weldforge.repository.UserRepository;
import tech.cwvermaak.weldforge.service.audit.AuditService;

import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Reserved slugs (`www`, `api`, `oauth`, `login`, …) must be rejected at
 * tenant-creation time, not just at resolution time. Otherwise an admin
 * can create a tenant whose subdomain the resolver will refuse to map —
 * a split-brain "exists but unreachable" state.
 */
class TenantServiceReservedSlugTest {

    private final TenantAccessor accessor = mock(TenantAccessor.class);
    private final TenantRepository tenantRepository = mock(TenantRepository.class);
    private final TenantSocialProviderRepository socialRepo = mock(TenantSocialProviderRepository.class);
    private final UserRepository userRepository = mock(UserRepository.class);
    private final RefreshTokenRepository refreshTokenRepository = mock(RefreshTokenRepository.class);
    private final TenantSlugHoldbackRepository slugHoldbackRepository = mock(TenantSlugHoldbackRepository.class);
    private final AuditService auditService = mock(AuditService.class);
    private final PublicHostProperties publicHost = publicHost();

    private final TenantService service = new TenantService(
            accessor, tenantRepository, socialRepo, userRepository,
            refreshTokenRepository, slugHoldbackRepository, auditService, publicHost,
            new TenantSlugValidator(publicHost, slugHoldbackRepository));

    @Test
    @DisplayName("Reserved slug 'oauth' is refused at creation")
    void reservedOauthRefused() {
        when(tenantRepository.existsBySlug(anyString())).thenReturn(false);
        TenantDto dto = TenantDto.builder()
                .slug("oauth").name("OAuth Inc").build();

        assertThatThrownBy(() -> service.createTenant(dto))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("reserved");
    }

    @Test
    @DisplayName("Reserved slug 'login' is refused at creation")
    void reservedLoginRefused() {
        when(tenantRepository.existsBySlug(anyString())).thenReturn(false);
        TenantDto dto = TenantDto.builder()
                .slug("login").name("Login Inc").build();

        assertThatThrownBy(() -> service.createTenant(dto))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("reserved");
    }

    @Test
    @DisplayName("Reserved slug 'api' is refused at creation")
    void reservedApiRefused() {
        when(tenantRepository.existsBySlug(anyString())).thenReturn(false);
        TenantDto dto = TenantDto.builder().slug("api").name("API Inc").build();

        assertThatThrownBy(() -> service.createTenant(dto))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("reserved");
    }

    @Test
    @DisplayName("Reserved-list rejection is case-insensitive (slug is lowercased first)")
    void reservedCaseInsensitive() {
        when(tenantRepository.existsBySlug(anyString())).thenReturn(false);
        TenantDto dto = TenantDto.builder().slug("ADMIN").name("Admin Co").build();

        assertThatThrownBy(() -> service.createTenant(dto))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("reserved");
    }

    @Test
    @DisplayName("Non-reserved slug 'acme' passes the reserved-list check")
    void normalSlugAllowed() {
        when(tenantRepository.existsBySlug(anyString())).thenReturn(false);
        when(tenantRepository.save(org.mockito.ArgumentMatchers.any(Tenant.class)))
                .thenAnswer(inv -> {
                    Tenant t = inv.getArgument(0);
                    t.setId(42L);
                    return t;
                });
        when(tenantRepository.findById(42L)).thenAnswer(inv ->
                Optional.of(Tenant.builder().id(42L).slug("acme").name("Acme").build()));

        // Should NOT throw IllegalArgumentException with "reserved".
        // (Other exceptions are fine — we're only asserting the reserved check passes.)
        try {
            service.createTenant(TenantDto.builder().slug("acme").name("Acme").build());
        } catch (IllegalArgumentException e) {
            org.assertj.core.api.Assertions.assertThat(e.getMessage())
                    .as("'acme' is not reserved — the failure must be unrelated")
                    .doesNotContain("reserved");
        } catch (RuntimeException ignored) {
            // Acceptable — the test only cares that the reserved check passes.
        }
    }

    private static PublicHostProperties publicHost() {
        PublicHostProperties p = new PublicHostProperties();
        p.setBaseDomain("sso.weldforge.org");
        p.setScheme("https");
        // Use the production reserved list so this test catches regressions
        // if a label is silently removed.
        // (Defaults from PublicHostProperties already contain api/admin/login/oauth.)
        return p;
    }
}
