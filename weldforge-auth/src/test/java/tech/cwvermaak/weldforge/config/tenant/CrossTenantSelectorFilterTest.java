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
}
