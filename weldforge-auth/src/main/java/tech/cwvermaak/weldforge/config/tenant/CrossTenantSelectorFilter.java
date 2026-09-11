package tech.cwvermaak.weldforge.config.tenant;

import jakarta.persistence.EntityNotFoundException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import tech.cwvermaak.weldforge.config.ApiProblem;
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
 * tenant are already in {@link TenantContext}. Every cross-tenant switch is
 * audited, successful and refused alike.
 *
 * <p><b>The only place an admin call changes tenant.</b> Until 2026-09-11 a
 * second channel existed: {@code JwtAuthenticationFilter} let an {@code sa}
 * token switch via {@code X-Tenant-Slug}, with a different eligibility rule, no
 * audit event, and a silent fall back to the home tenant for an unknown slug.
 * The admin portal used that channel, and a write aimed at one tenant landed
 * in another with no error. So on an <i>authenticated</i> admin call,
 * {@code X-Tenant-Slug} is now read here as an alias of {@code X-WF-Tenant}:
 * one rule (memberships), one audit trail, and a refusal instead of a fallback.
 * Before authentication {@code X-Tenant-Slug} keeps its other meaning -- the
 * tenant a sign-in or sign-up is for -- and this filter ignores it.
 *
 * <p>Every admin response carries {@value #ACTING_TENANT_HEADER}, the tenant
 * the request actually acted in, so a client can check it got what it asked
 * for instead of trusting that it did.
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class CrossTenantSelectorFilter extends OncePerRequestFilter {

    public static final String HEADER = "X-WF-Tenant";
    /** Honoured as an alias of {@link #HEADER} on authenticated admin calls only. */
    public static final String LEGACY_HEADER = TenantResolverFilter.HEADER;
    /** Response header: the tenant this admin request acted in. */
    public static final String ACTING_TENANT_HEADER = "X-WF-Acting-Tenant";

    private final TenantAccessor tenantAccessor;
    private final AuditService auditService;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        String path = request.getRequestURI();
        if (path == null || !path.startsWith("/api/admin/")) {
            filterChain.doFilter(request, response);
            return;
        }

        String explicit = normalized(request.getHeader(HEADER));
        String legacy = authenticated() ? normalized(request.getHeader(LEGACY_HEADER)) : null;
        String homeSlug = TenantContext.get();

        if (explicit != null && legacy != null && !explicit.equals(legacy)) {
            // Two selectors naming different tenants: guessing which one was
            // meant is exactly the failure this filter exists to prevent.
            auditDenied(homeSlug, explicit, "conflicting_selectors");
            ApiProblem.write(response, ApiProblem.body(HttpStatus.BAD_REQUEST, "tenant_selector_conflict",
                    HEADER + " names '" + explicit + "' but " + LEGACY_HEADER + " names '" + legacy
                            + "'; send one tenant selector", request));
            return;
        }

        String targetSlug = explicit != null ? explicit : legacy;
        String channel = explicit != null ? HEADER : LEGACY_HEADER;
        if (targetSlug != null && !targetSlug.equals(homeSlug)) {
            try {
                AdminRole role = tenantAccessor.switchToTenant(targetSlug);
                audit(homeSlug, targetSlug, role, channel);
            } catch (EntityNotFoundException e) {
                // B-TEN-2: record refused switches so cross-tenant probing /
                // lateral-movement reconnaissance leaves an audit trail.
                auditDenied(homeSlug, targetSlug, "unknown_tenant");
                ApiProblem.write(response, ApiProblem.body(HttpStatus.NOT_FOUND, "unknown_tenant",
                        "Unknown tenant '" + targetSlug + "' in " + channel, request));
                return;
            } catch (AccessDeniedException e) {
                auditDenied(homeSlug, targetSlug, "no_membership");
                ApiProblem.write(response, ApiProblem.body(HttpStatus.FORBIDDEN, "tenant_access_denied",
                        e.getMessage() + " -- the request was NOT run in your home tenant instead", request));
                return;
            }
        }

        String acting = TenantContext.get();
        if (acting != null) {
            response.setHeader(ACTING_TENANT_HEADER, acting);
        }
        filterChain.doFilter(request, response);
    }

    private static String normalized(String header) {
        return header == null || header.isBlank() ? null : header.trim().toLowerCase();
    }

    private static boolean authenticated() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        return auth != null && auth.isAuthenticated() && !(auth instanceof AnonymousAuthenticationToken);
    }

    private void audit(String homeSlug, String targetSlug, AdminRole role, String channel) {
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
                        "selector", channel,
                        "actor", actor)));
        log.info("cross_tenant_admin home={} target={} role={} selector={} actor={}",
                homeSlug, targetSlug, role, channel, actor);
    }

    private void auditDenied(String homeSlug, String targetSlug, String reason) {
        Long userId = TenantContext.getActorUserId();
        Long svcId = TenantContext.getActorServiceAccountId();
        String actor = userId != null ? "user:" + userId
                : svcId != null ? "service_account:" + svcId : "unknown";
        auditService.log(AuditEvent.builder()
                .eventType(AuditEventTypes.ADMIN_CROSS_TENANT_DENIED)
                .outcome(AuditEvent.Outcome.DENIED)
                .targetType(AuditEventTypes.TARGET_TENANT)
                .targetId(targetSlug)
                .metadata(AuditService.meta(
                        "home_tenant", homeSlug == null ? "unknown" : homeSlug,
                        "target_tenant", targetSlug,
                        "reason", reason,
                        "actor", actor)));
        log.warn("cross_tenant_admin_denied home={} target={} reason={} actor={}",
                homeSlug, targetSlug, reason, actor);
    }
}
