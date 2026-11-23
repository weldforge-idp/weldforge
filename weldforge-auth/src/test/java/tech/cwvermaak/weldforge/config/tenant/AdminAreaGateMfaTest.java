package tech.cwvermaak.weldforge.config.tenant;

import jakarta.servlet.FilterChain;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.util.ReflectionTestUtils;
import tech.cwvermaak.weldforge.model.AdminRole;
import tech.cwvermaak.weldforge.model.MfaFactor;
import tech.cwvermaak.weldforge.repository.MfaFactorRepository;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * WF-6 — {@link AdminAreaGateFilter} requires a verified second factor of an
 * admin once the flag is on. Service accounts are exempt and the flag defaults
 * off, so nothing changes for the test suite or local dev.
 */
class AdminAreaGateMfaTest {

    private TenantAccessor tenantAccessor;
    private MfaFactorRepository mfaFactorRepository;
    private AdminAreaGateFilter filter;

    @BeforeEach
    void setUp() {
        tenantAccessor = mock(TenantAccessor.class);
        mfaFactorRepository = mock(MfaFactorRepository.class);
        filter = new AdminAreaGateFilter(tenantAccessor, mfaFactorRepository);
        ReflectionTestUtils.setField(filter, "requireAdminMfa", true);

        SecurityContextHolder.getContext().setAuthentication(
                new UsernamePasswordAuthenticationToken("admin@acme.test", "n/a",
                        AuthorityUtils.NO_AUTHORITIES));
        TenantContext.set("acme", 1L, AdminRole.TENANT_ADMIN);
        when(tenantAccessor.effectiveRole(1L)).thenReturn(AdminRole.TENANT_ADMIN);
    }

    @AfterEach
    void tearDown() {
        TenantContext.clear();
        SecurityContextHolder.clearContext();
    }

    private MockHttpServletRequest adminRequest() {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/admin/roles");
        request.setServletPath("/api/admin/roles");
        return request;
    }

    @Test
    @DisplayName("an admin with no verified factor is refused mfa_enrolment_required")
    void adminWithoutFactorRefused() throws Exception {
        TenantContext.setActorUser(42L);
        when(mfaFactorRepository.findByUserIdAndEnabledTrueAndVerifiedTrue(42L)).thenReturn(List.of());
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain chain = mock(FilterChain.class);

        filter.doFilter(adminRequest(), response, chain);

        assertThat(response.getStatus()).isEqualTo(403);
        assertThat(response.getContentAsString()).contains("mfa_enrolment_required");
        verify(chain, never()).doFilter(any(), any());
    }

    @Test
    @DisplayName("an admin with a verified factor passes through")
    void adminWithFactorPasses() throws Exception {
        TenantContext.setActorUser(42L);
        when(mfaFactorRepository.findByUserIdAndEnabledTrueAndVerifiedTrue(42L))
                .thenReturn(List.of(mock(MfaFactor.class)));
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain chain = mock(FilterChain.class);

        filter.doFilter(adminRequest(), response, chain);

        verify(chain).doFilter(any(), any());
        assertThat(response.getStatus()).isEqualTo(200);
    }

    @Test
    @DisplayName("a service-account admin is exempt — a machine credential has no interactive factor")
    void serviceAccountExempt() throws Exception {
        TenantContext.setActorServiceAccount(7L);
        // No verified factor exists, but it must never be consulted for a service account.
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain chain = mock(FilterChain.class);

        filter.doFilter(adminRequest(), response, chain);

        verify(chain).doFilter(any(), any());
        verify(mfaFactorRepository, never()).findByUserIdAndEnabledTrueAndVerifiedTrue(anyLong());
    }

    @Test
    @DisplayName("with the flag off, a factorless admin is not gated")
    void flagOffNoEnforcement() throws Exception {
        ReflectionTestUtils.setField(filter, "requireAdminMfa", false);
        TenantContext.setActorUser(42L);
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain chain = mock(FilterChain.class);

        filter.doFilter(adminRequest(), response, chain);

        verify(chain).doFilter(any(), any());
        verify(mfaFactorRepository, never()).findByUserIdAndEnabledTrueAndVerifiedTrue(anyLong());
    }

    @Test
    @DisplayName("a non-admin is still refused admin_role_required, before the MFA check")
    void nonAdminStillRefusedForRole() throws Exception {
        TenantContext.set("acme", 1L, AdminRole.NONE);
        TenantContext.setActorUser(99L);
        when(tenantAccessor.effectiveRole(1L)).thenReturn(AdminRole.NONE);
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain chain = mock(FilterChain.class);

        filter.doFilter(adminRequest(), response, chain);

        assertThat(response.getStatus()).isEqualTo(403);
        assertThat(response.getContentAsString()).contains("admin_role_required");
        verify(chain, never()).doFilter(any(), any());
    }
}
