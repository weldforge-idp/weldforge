package tech.cwvermaak.weldforge.config.tenant;

import jakarta.persistence.EntityNotFoundException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import tech.cwvermaak.weldforge.model.AdminRole;
import tech.cwvermaak.weldforge.model.AuditEvent;
import tech.cwvermaak.weldforge.service.audit.AuditEventTypes;
import tech.cwvermaak.weldforge.service.audit.AuditService;

import java.io.IOException;

/**
 * Cross-tenant admin selector — {@code cross-tenant-admin-spec.md} §6.1.
 *
 * <p>When an authenticated admin call to {@code /api/admin/**} carries an
 * {@code X-WF-Tenant: <slug>} header naming a tenant other than the caller's
 * home tenant, this filter re-resolves the request's tenant context to that
 * target and recomputes the caller's admin role for it from their admin
 * memberships ({@link TenantAccessor#switchToTenant(String)}).
 *
 * <p>It does not itself grant anything: it only rebinds {@link TenantContext}
 * to the target with the caller's <i>effective</i> role. The existing
 * per-endpoint {@code TenantAccessor} guards ({@code requireTenantAdmin} etc.)
 * then enforce that role, so a caller with no reach into the target is
 * rejected by the normal authorization path. A caller with no admin role at
 * all for the target is rejected here, up front, with 403.
 *
 * <p>Runs after the authentication filters so the caller's identity and home
 * tenant are already in {@link TenantContext}. Every successful cross-tenant
 * switch is audited.
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class CrossTenantSelectorFilter extends OncePerRequestFilter {

    public static final String HEADER = "X-WF-Tenant";

    private final TenantAccessor tenantAccessor;
    private final AuditService auditService;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        String path = request.getRequestURI();
        String target = request.getHeader(HEADER);

        // Only admin endpoints honour the selector, and only when it is present.
        if (path == null || !path.startsWith("/api/admin/")
                || target == null || target.isBlank()) {
            filterChain.doFilter(request, response);
            return;
        }

        String targetSlug = target.trim().toLowerCase();
        String homeSlug = TenantContext.get();
        if (targetSlug.equals(homeSlug)) {
            // Selecting your own tenant is a no-op — nothing to re-resolve.
            filterChain.doFilter(request, response);
            return;
        }

        try {
            AdminRole role = tenantAccessor.switchToTenant(targetSlug);
            audit(homeSlug, targetSlug, role);
        } catch (EntityNotFoundException e) {
            response.setStatus(HttpServletResponse.SC_NOT_FOUND);
            response.getWriter().write("Unknown X-WF-Tenant: " + targetSlug);
            return;
        } catch (AccessDeniedException e) {
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            response.getWriter().write(e.getMessage());
            return;
        }
        filterChain.doFilter(request, response);
    }

    private void audit(String homeSlug, String targetSlug, AdminRole role) {
        Long userId = TenantContext.getActorUserId();
        Long svcId = TenantContext.getActorServiceAccountId();
        String actor = userId != null ? "user:" + userId
                : svcId != null ? "service_account:" + svcId : "unknown";
        auditService.log(AuditEvent.builder()
                .eventType(AuditEventTypes.ADMIN_CROSS_TENANT_ACCESS)
                .outcome(AuditEvent.Outcome.SUCCESS)
                .targetType(AuditEventTypes.TARGET_TENANT)
                .targetId(targetSlug)
                .metadata(AuditService.meta(
                        "home_tenant", homeSlug == null ? "unknown" : homeSlug,
                        "target_tenant", targetSlug,
                        "effective_role", role.name(),
                        "actor", actor)));
        log.info("cross_tenant_admin home={} target={} role={} actor={}",
                homeSlug, targetSlug, role, actor);
    }
}
