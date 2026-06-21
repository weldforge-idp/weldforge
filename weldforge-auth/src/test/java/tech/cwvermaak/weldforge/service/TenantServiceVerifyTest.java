package tech.cwvermaak.weldforge.service;

import jakarta.persistence.EntityNotFoundException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.security.access.AccessDeniedException;
import tech.cwvermaak.weldforge.config.tenant.PublicHostProperties;
import tech.cwvermaak.weldforge.config.tenant.TenantAccessor;
import tech.cwvermaak.weldforge.model.Tenant;
import tech.cwvermaak.weldforge.model.dto.TenantDto;
import tech.cwvermaak.weldforge.repository.RefreshTokenRepository;
import tech.cwvermaak.weldforge.repository.TenantRepository;
import tech.cwvermaak.weldforge.repository.TenantSlugHoldbackRepository;
import tech.cwvermaak.weldforge.repository.TenantSocialProviderRepository;
import tech.cwvermaak.weldforge.repository.UserRepository;
import tech.cwvermaak.weldforge.service.audit.AuditEventTypes;
import tech.cwvermaak.weldforge.service.audit.AuditService;

import java.time.LocalDateTime;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Tenant identity-proofing — verify/unverify SUPER_ADMIN action.
 * See {@code docs/auth-url-spec.md} §"Tenant identity-proofing".
 */
class TenantServiceVerifyTest {

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
    @DisplayName("verifyTenant flips verifiedAt and emits tenant.verified audit event")
    void verify_setsTimestampAndAudits() {
        Tenant t = Tenant.builder().id(7L).slug("acme").name("Acme").build();
        when(tenantRepository.findById(7L)).thenReturn(Optional.of(t));
        when(tenantRepository.save(any(Tenant.class))).thenAnswer(inv -> inv.getArgument(0));

        TenantDto result = service.verifyTenant(7L);

        assertThat(result.getVerifiedAt()).isNotNull();
        assertThat(t.getVerifiedAt()).isNotNull();
        verify(auditService).recordAdmin(
                eq(AuditEventTypes.TENANT_VERIFIED), any(),
                eq(AuditEventTypes.TARGET_TENANT), eq("7"), any());
    }

    @Test
    @DisplayName("unverifyTenant clears verifiedAt and emits tenant.unverified audit event")
    void unverify_clearsTimestampAndAudits() {
        Tenant t = Tenant.builder().id(7L).slug("acme").name("Acme")
                .verifiedAt(LocalDateTime.now().minusDays(5))
                .verifiedByUserId(42L)
                .build();
        when(tenantRepository.findById(7L)).thenReturn(Optional.of(t));
        when(tenantRepository.save(any(Tenant.class))).thenAnswer(inv -> inv.getArgument(0));

        TenantDto result = service.unverifyTenant(7L);

        assertThat(result.getVerifiedAt()).isNull();
        assertThat(t.getVerifiedAt()).isNull();
        assertThat(t.getVerifiedByUserId()).isNull();
        verify(auditService).recordAdmin(
                eq(AuditEventTypes.TENANT_UNVERIFIED), any(),
                eq(AuditEventTypes.TARGET_TENANT), eq("7"), any());
    }

    @Test
    @DisplayName("verifyTenant refuses non-super-admin callers")
    void verify_rejectsNonSuperAdmin() {
        doThrow(new AccessDeniedException("super admin required"))
                .when(accessor).requireSuperAdmin();

        assertThatThrownBy(() -> service.verifyTenant(7L))
                .isInstanceOf(AccessDeniedException.class);
    }

    @Test
    @DisplayName("unverifyTenant refuses non-super-admin callers")
    void unverify_rejectsNonSuperAdmin() {
        doThrow(new AccessDeniedException("super admin required"))
                .when(accessor).requireSuperAdmin();

        assertThatThrownBy(() -> service.unverifyTenant(7L))
                .isInstanceOf(AccessDeniedException.class);
    }

    @Test
    @DisplayName("verifyTenant on unknown id throws EntityNotFoundException")
    void verify_unknownIdThrows() {
        when(tenantRepository.findById(999L)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.verifyTenant(999L))
                .isInstanceOf(EntityNotFoundException.class);
    }

    @Test
    @DisplayName("Branding endpoint exposes verified=false for never-verified tenant")
    void branding_exposesVerifiedFalse() {
        Tenant t = Tenant.builder().id(7L).slug("acme").name("Acme").build();
        when(tenantRepository.findBySlug("acme")).thenReturn(Optional.of(t));

        assertThat(service.getBrandingForSlug("acme").getVerified()).isFalse();
    }

    @Test
    @DisplayName("Branding endpoint exposes verified=true after explicit verification")
    void branding_exposesVerifiedTrue() {
        Tenant t = Tenant.builder().id(7L).slug("acme").name("Acme")
                .verifiedAt(LocalDateTime.now().minusDays(1))
                .build();
        when(tenantRepository.findBySlug("acme")).thenReturn(Optional.of(t));

        assertThat(service.getBrandingForSlug("acme").getVerified()).isTrue();
    }

    @Test
    @DisplayName("verifyTenant on already-verified tenant updates timestamp and records re-verification")
    void reVerify_recordsFlag() {
        Tenant t = Tenant.builder().id(7L).slug("acme").name("Acme")
                .verifiedAt(LocalDateTime.now().minusDays(30))
                .build();
        when(tenantRepository.findById(7L)).thenReturn(Optional.of(t));
        when(tenantRepository.save(any(Tenant.class))).thenAnswer(inv -> inv.getArgument(0));

        service.verifyTenant(7L);

        ArgumentCaptor<java.util.Map<String, Object>> metaCaptor =
                ArgumentCaptor.forClass(java.util.Map.class);
        verify(auditService).recordAdmin(
                eq(AuditEventTypes.TENANT_VERIFIED), any(),
                anyString(), anyString(), metaCaptor.capture());
        assertThat(metaCaptor.getValue()).containsEntry("re_verification", true);
    }

    @Test
    @DisplayName("updateTenant cannot flip verifiedAt — only the explicit endpoint can")
    void update_cannotFlipVerified() {
        Tenant t = Tenant.builder().id(7L).slug("acme").name("Acme").build();
        when(tenantRepository.findById(7L)).thenReturn(Optional.of(t));
        when(tenantRepository.save(any(Tenant.class))).thenAnswer(inv -> inv.getArgument(0));

        // Construct an update payload that ATTEMPTS to set verifiedAt.
        TenantDto attack = TenantDto.builder()
                .verifiedAt(LocalDateTime.now())
                .verifiedByUserId(999L)
                .build();
        service.updateTenant(7L, attack);

        assertThat(t.getVerifiedAt())
                .as("regular update path must not promote a tenant to verified")
                .isNull();
        assertThat(t.getVerifiedByUserId()).isNull();
    }

    private static PublicHostProperties publicHost() {
        PublicHostProperties p = new PublicHostProperties();
        p.setBaseDomain("sso.weldforge.org");
        p.setScheme("https");
        return p;
    }
}
