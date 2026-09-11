package tech.cwvermaak.weldforge.config.tenant;

import jakarta.persistence.EntityNotFoundException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.security.access.AccessDeniedException;
import tech.cwvermaak.weldforge.model.AdminRole;
import tech.cwvermaak.weldforge.model.AuditEvent;
import tech.cwvermaak.weldforge.service.audit.AuditEventTypes;
import tech.cwvermaak.weldforge.service.audit.AuditService;

import java.io.PrintWriter;
import java.io.StringWriter;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/**
 * B-TEN-2: every cross-tenant switch attempt is audited — successes AND
 * refusals (unknown tenant / no membership), so probing leaves a trail.
 */
class CrossTenantSelectorFilterTest {

    private TenantAccessor tenantAccessor;
    private AuditService auditService;
    private CrossTenantSelectorFilter filter;

    @BeforeEach
    void setUp() {
        tenantAccessor = mock(TenantAccessor.class);
        auditService = mock(AuditService.class);
        filter = new CrossTenantSelectorFilter(tenantAccessor, auditService);
        TenantContext.set("acme", 1L, AdminRole.SUPER_ADMIN);
    }

    @AfterEach
    void clear() {
        TenantContext.clear();
    }

    private static HttpServletRequest req() {
        HttpServletRequest r = mock(HttpServletRequest.class);
        when(r.getRequestURI()).thenReturn("/api/admin/users");
        when(r.getHeader(CrossTenantSelectorFilter.HEADER)).thenReturn("globex");
        return r;
    }

    private static HttpServletResponse resp() throws Exception {
        HttpServletResponse r = mock(HttpServletResponse.class);
        when(r.getWriter()).thenReturn(new PrintWriter(new StringWriter()));
        return r;
    }

    private String auditedEventType() {
        ArgumentCaptor<AuditEvent.AuditEventBuilder> cap =
                ArgumentCaptor.forClass(AuditEvent.AuditEventBuilder.class);
        verify(auditService).log(cap.capture());
        return cap.getValue().build().getEventType();
    }

    @Test
    @DisplayName("a successful switch is audited as cross_tenant.access and proceeds")
    void success_audited() throws Exception {
        when(tenantAccessor.switchToTenant("globex")).thenReturn(AdminRole.TENANT_ADMIN);
        FilterChain chain = mock(FilterChain.class);

        filter.doFilterInternal(req(), resp(), chain);

        assertThat(auditedEventType()).isEqualTo(AuditEventTypes.ADMIN_CROSS_TENANT_ACCESS);
        verify(chain).doFilter(any(), any());
    }

    @Test
    @DisplayName("an unknown target tenant is audited as cross_tenant.denied and 404s")
    void unknownTenant_auditedDenied() throws Exception {
        when(tenantAccessor.switchToTenant("globex")).thenThrow(new EntityNotFoundException("nope"));
        FilterChain chain = mock(FilterChain.class);
        HttpServletResponse res = resp();

        filter.doFilterInternal(req(), res, chain);

        assertThat(auditedEventType()).isEqualTo(AuditEventTypes.ADMIN_CROSS_TENANT_DENIED);
        verify(res).setStatus(HttpServletResponse.SC_NOT_FOUND);
        verify(chain, never()).doFilter(any(), any());
    }

    @Test
    @DisplayName("a switch with no membership reach is audited as cross_tenant.denied and 403s")
    void noMembership_auditedDenied() throws Exception {
        when(tenantAccessor.switchToTenant("globex")).thenThrow(new AccessDeniedException("no reach"));
        FilterChain chain = mock(FilterChain.class);
        HttpServletResponse res = resp();

        filter.doFilterInternal(req(), res, chain);

        assertThat(auditedEventType()).isEqualTo(AuditEventTypes.ADMIN_CROSS_TENANT_DENIED);
        verify(res).setStatus(HttpServletResponse.SC_FORBIDDEN);
        verify(chain, never()).doFilter(any(), any());
    }

    // ---- 2026-09-11: one selector path, no silent fallback -----------------

    private static void signIn() {
        org.springframework.security.core.context.SecurityContextHolder.getContext().setAuthentication(
                new org.springframework.security.authentication.UsernamePasswordAuthenticationToken(
                        "super@acme.test", null, java.util.List.of()));
    }

    @AfterEach
    void signOut() {
        org.springframework.security.core.context.SecurityContextHolder.clearContext();
    }

    private static org.springframework.mock.web.MockHttpServletRequest adminCall() {
        return new org.springframework.mock.web.MockHttpServletRequest("POST", "/api/admin/oidc/clients");
    }

    @Test
    @DisplayName("On an authenticated admin call, X-Tenant-Slug is the same audited selector as X-WF-Tenant")
    void legacyHeaderRoutesThroughTheSameSwitch() throws Exception {
        signIn();
        when(tenantAccessor.switchToTenant("cwvermaak-tech")).thenAnswer(inv -> {
            TenantContext.set("cwvermaak-tech", 9L, AdminRole.SUPER_ADMIN);
            return AdminRole.SUPER_ADMIN;
        });
        var request = adminCall();
        request.addHeader("X-Tenant-Slug", "cwvermaak-tech");
        var response = new org.springframework.mock.web.MockHttpServletResponse();
        FilterChain chain = mock(FilterChain.class);

        filter.doFilterInternal(request, response, chain);

        verify(tenantAccessor).switchToTenant("cwvermaak-tech");
        ArgumentCaptor<AuditEvent.AuditEventBuilder> cap = ArgumentCaptor.forClass(AuditEvent.AuditEventBuilder.class);
        verify(auditService).log(cap.capture());
        AuditEvent event = cap.getValue().build();
        assertThat(event.getEventType()).isEqualTo(AuditEventTypes.ADMIN_CROSS_TENANT_ACCESS);
        assertThat(event.getMetadata()).containsEntry("selector", "X-Tenant-Slug");
        assertThat(response.getHeader(CrossTenantSelectorFilter.ACTING_TENANT_HEADER)).isEqualTo("cwvermaak-tech");
        verify(chain).doFilter(any(), any());
    }

    @Test
    @DisplayName("A selector the caller cannot use is refused -- never run in the home tenant instead")
    void unusableSelectorIsRefusedNotIgnored() throws Exception {
        // The failure of 2026-09-11: a write naming one tenant succeeded in
        // another. adm=SUPER_ADMIN with no global membership has no reach.
        signIn();
        when(tenantAccessor.switchToTenant("cwvermaak-tech"))
                .thenThrow(new AccessDeniedException("Caller has no admin membership for tenant 'cwvermaak-tech'"));
        var request = adminCall();
        request.addHeader("X-Tenant-Slug", "cwvermaak-tech");
        var response = new org.springframework.mock.web.MockHttpServletResponse();
        FilterChain chain = mock(FilterChain.class);

        filter.doFilterInternal(request, response, chain);

        assertThat(response.getStatus()).isEqualTo(403);
        assertThat(response.getContentType()).startsWith("application/problem+json");
        assertThat(response.getContentAsString())
                .contains("tenant_access_denied")
                .contains("NOT run in your home tenant");
        assertThat(auditedEventType()).isEqualTo(AuditEventTypes.ADMIN_CROSS_TENANT_DENIED);
        verify(chain, never()).doFilter(any(), any());
    }

    @Test
    @DisplayName("Two selectors naming different tenants are refused, not guessed between")
    void conflictingSelectorsRefused() throws Exception {
        signIn();
        var request = adminCall();
        request.addHeader("X-WF-Tenant", "globex");
        request.addHeader("X-Tenant-Slug", "initech");
        var response = new org.springframework.mock.web.MockHttpServletResponse();
        FilterChain chain = mock(FilterChain.class);

        filter.doFilterInternal(request, response, chain);

        assertThat(response.getStatus()).isEqualTo(400);
        assertThat(response.getContentAsString()).contains("tenant_selector_conflict");
        verify(tenantAccessor, never()).switchToTenant(any());
        assertThat(auditedEventType()).isEqualTo(AuditEventTypes.ADMIN_CROSS_TENANT_DENIED);
        verify(chain, never()).doFilter(any(), any());
    }

    @Test
    @DisplayName("Both selectors naming the same tenant are fine")
    void agreeingSelectorsAccepted() throws Exception {
        signIn();
        when(tenantAccessor.switchToTenant("globex")).thenReturn(AdminRole.TENANT_ADMIN);
        var request = adminCall();
        request.addHeader("X-WF-Tenant", "Globex");
        request.addHeader("X-Tenant-Slug", "globex");
        FilterChain chain = mock(FilterChain.class);

        filter.doFilterInternal(request, new org.springframework.mock.web.MockHttpServletResponse(), chain);

        verify(tenantAccessor).switchToTenant("globex");
        verify(chain).doFilter(any(), any());
    }

    @Test
    @DisplayName("Before authentication, X-Tenant-Slug is not a selector (it names the sign-in tenant)")
    void legacyHeaderIgnoredWhenUnauthenticated() throws Exception {
        var request = adminCall();
        request.addHeader("X-Tenant-Slug", "globex");
        FilterChain chain = mock(FilterChain.class);

        filter.doFilterInternal(request, new org.springframework.mock.web.MockHttpServletResponse(), chain);

        verifyNoInteractions(tenantAccessor);
        verify(chain).doFilter(any(), any());
    }

    @Test
    @DisplayName("A selector naming your own tenant is a no-op, and the acting tenant is still echoed")
    void ownTenantNoOpStillEchoed() throws Exception {
        signIn();
        var request = adminCall();
        request.addHeader("X-Tenant-Slug", "acme");
        var response = new org.springframework.mock.web.MockHttpServletResponse();

        filter.doFilterInternal(request, response, mock(FilterChain.class));

        verifyNoInteractions(tenantAccessor, auditService);
        assertThat(response.getHeader(CrossTenantSelectorFilter.ACTING_TENANT_HEADER)).isEqualTo("acme");
    }

    @Test
    @DisplayName("Non-admin paths are untouched: no selector, no echo")
    void nonAdminPathsUntouched() throws Exception {
        signIn();
        var request = new org.springframework.mock.web.MockHttpServletRequest("GET", "/api/auth/me");
        request.addHeader("X-WF-Tenant", "globex");
        var response = new org.springframework.mock.web.MockHttpServletResponse();

        filter.doFilterInternal(request, response, mock(FilterChain.class));

        verifyNoInteractions(tenantAccessor);
        assertThat(response.getHeader(CrossTenantSelectorFilter.ACTING_TENANT_HEADER)).isNull();
    }
}
